import fs from 'fs/promises';
import matter from 'gray-matter';
import yaml from 'js-yaml';
import path from 'path';
import { timestampFile } from './utils/fsx.js';
import { logStep } from './utils/logger.js';
import { extractFindings, severityCounts, topSeverity } from './utils/findings.js';
import { notify } from './utils/notify.js';

// Import executors
import * as dnsExec from './executors/dns.js';
import * as whoisExec from './executors/whois.js';
import * as nmapExec from './executors/nmap.js';
import * as httpExec from './executors/http.js';
import * as tlsExec from './executors/tls.js';
import * as subsExec from './executors/subdomains.js';
import * as pingExec from './executors/ping.js';
import * as tracerouteExec from './executors/traceroute.js';
import * as emailExec from './executors/email.js';
import * as ipExec from './executors/ip.js';
import * as vulnExec from './executors/vuln.js';
import * as shodanExec from './executors/shodan.js';
import * as cloudExec from './executors/cloud.js';

// Registry mapping playbook 'uses' strings to executor functions
const registry = {
  'dns.resolve': dnsExec.resolveDNS,
  'dns.reverse': dnsExec.reverseDNS,
  'whois.lookup': whoisExec.lookupWhois,
  'nmap.scan': nmapExec.scanNmap,
  'http.headers': httpExec.getHeaders,
  'http.get': httpExec.getPath,
  'http.security_score': httpExec.securityScore,
  'http.waf_detect': httpExec.wafDetect,
  'http.fingerprint': httpExec.fingerprint,
  'http.fuzz_paths': httpExec.fuzzPaths,
  'http.git_leak': httpExec.gitLeak,
  'http.cors_check': httpExec.corsCheck,
  'http.methods': httpExec.methods,
  'tls.inspect': tlsExec.inspectTLS,
  'tls.deep': tlsExec.deepTLS,
  'subdomains.passive': subsExec.passive,
  'network.ping': pingExec.ping,
  'network.traceroute': tracerouteExec.traceroute,
  'email.security': emailExec.security,
  'ip.intel': ipExec.intel,
  'vuln.cve_lookup': vulnExec.cveLookup,
  'shodan.host': shodanExec.hostLookup,
  'cloud.bucket_finder': cloudExec.bucketFinder
};

// Replace templates like {{vars.target}} with values from context
function applyTemplate(str, ctx) {
  if (typeof str !== 'string') return str;
  const result = str.replace(/\{\{\s*([^}]+?)\s*\}\}/g, (_, k) => {
    const parts = k.split('.');
    let v = ctx;
    for (const p of parts) v = v?.[p];
    return v ?? '';
  });
  
  // If the entire string was a template and resulted in a number, return as number
  if (str.match(/^\{\{\s*[^}]+?\s*\}\}$/) && !isNaN(result) && result !== '') {
    return Number(result);
  }
  
  return result;
}

function deepTemplate(obj, ctx) {
  if (obj == null) return obj;
  if (typeof obj === 'string') return applyTemplate(obj, ctx);
  if (Array.isArray(obj)) return obj.map(v => deepTemplate(v, ctx));
  if (typeof obj === 'object') {
    const out = {};
    for (const k of Object.keys(obj)) out[k] = deepTemplate(obj[k], ctx);
    return out;
  }
  return obj;
}

function withTimeout(promise, ms, label = 'operation') {
  if (!ms || ms <= 0) return promise;
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    promise.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); }
    );
  });
}

export async function runPlaybook({ playbookPath, outDir, varOverrides = {}, stepTimeoutMs }) {
  // Load playbook and parse YAML front matter
  const raw = await fs.readFile(playbookPath, 'utf8');
  const { data: fm, content } = matter(raw, { engines: { yaml: s => yaml.load(s) } });

  const ctx = { vars: { ...(fm.vars || {}), ...varOverrides } };
  const steps = fm.steps || [];
  const outputs = new Array(steps.length);
  const startedAt = new Date().toISOString();
  const title = fm.title || fm.id || path.basename(playbookPath);

  // Execute one step and return its output object (caller controls ordering).
  const runStep = async (step, i) => {
    const stepCtx = deepTemplate(step, { ...ctx, content, fm });
    const fn = registry[stepCtx.uses];
    if (!fn) {
      return { name: stepCtx.name, uses: stepCtx.uses, error: `Unknown executor` };
    }
    logStep(i + 1, stepCtx.name, stepCtx.uses);
    try {
      const effTimeout = stepCtx.with?.timeoutMs ?? stepTimeoutMs;
      const execPromise = fn(ctx.vars.target, stepCtx.with || {});
      const res = await withTimeout(execPromise, effTimeout, stepCtx.name);
      return { name: stepCtx.name, uses: stepCtx.uses, ok: true, data: res };
    } catch (e) {
      return { name: stepCtx.name, uses: stepCtx.uses, ok: false, error: String(e?.message || e) };
    }
  };

  // Steps run sequentially by default. Consecutive steps flagged `parallel: true`
  // form a batch that runs concurrently; a non-parallel step is a barrier.
  // Output order always matches declaration order (indexed writes).
  let si = 0;
  while (si < steps.length) {
    if (steps[si].parallel) {
      const batch = [];
      while (si < steps.length && steps[si].parallel) { batch.push(si); si++; }
      await Promise.all(batch.map(idx => runStep(steps[idx], idx).then(out => { outputs[idx] = out; })));
    } else {
      outputs[si] = await runStep(steps[si], si);
      si++;
    }
  }

  const endedAt = new Date().toISOString();
  const report = { playbook: { id: fm.id, title, path: playbookPath }, vars: ctx.vars, startedAt, endedAt, outputs };

  // Aggregate severity-rated findings across all steps for the executive summary,
  // risk matrix, and webhook notifications.
  const findings = extractFindings(report);
  const counts = severityCounts(findings);
  report.findings = findings;
  report.severityCounts = counts;
  report.topSeverity = findings.length ? topSeverity(findings) : null;

  const base = timestampFile(title.replace(/\s+/g, '_'));
  const jsonPath = path.join(outDir, `${base}.json`);
  await fs.writeFile(jsonPath, JSON.stringify(report, null, 2));

  // Build Markdown report — executive summary + risk matrix first, then details.
  const mdParts = [
    `# ${title}`,
    `- Target: **${ctx.vars.target}**`,
    `- Started: ${startedAt}`,
    `- Ended: ${endedAt}`,
    '',
    '## Executive Summary',
    '',
    findings.length
      ? `**${findings.length}** finding(s) — top severity: **${(report.topSeverity || 'info').toUpperCase()}**.`
      : 'No severity-rated findings.',
    '',
    '| Critical | High | Medium | Low | Info |',
    '| -------- | ---- | ------ | --- | ---- |',
    `| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |`,
    '',
  ];
  if (findings.length) {
    mdParts.push('### Findings', '');
    for (const f of findings.slice(0, 50)) {
      mdParts.push(`- **[${f.severity.toUpperCase()}]** ${f.message} — \`${f.uses}\` (${f.step})`);
    }
    mdParts.push('');
  }
  mdParts.push('## Steps & Results');
  for (const o of outputs) {
    mdParts.push(`### ${o.name} \`(${o.uses})\``);
    if (o.ok) {
      mdParts.push(`<details><summary>Success</summary>\n\n\`\`\`json\n${JSON.stringify(o.data, null, 2)}\n\`\`\`\n</details>`);
    } else {
      mdParts.push(`❌ **Failed**: ${o.error}`);
    }
    mdParts.push('');
  }
  const mdPath = path.join(outDir, `${base}.md`);
  await fs.writeFile(mdPath, mdParts.join('\n'));

  // Fire webhook notifications (no-op unless a webhook env var is set). Never
  // let a notification failure break the run.
  const notification = await notify({ report, jsonPath, mdPath }).catch(e => ({ sent: false, reason: e.message }));

  return { jsonPath, mdPath, report, notification };
}
