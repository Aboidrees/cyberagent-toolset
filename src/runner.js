import fs from 'fs/promises';
import matter from 'gray-matter';
import yaml from 'js-yaml';
import path from 'path';
import { timestampFile } from './utils/fsx.js';
import { logStep } from './utils/logger.js';

// Import executors
import * as dnsExec from './executors/dns.js';
import * as whoisExec from './executors/whois.js';
import * as nmapExec from './executors/nmap.js';
import * as httpExec from './executors/http.js';
import * as tlsExec from './executors/tls.js';
import * as subsExec from './executors/subdomains.js';
import * as pingExec from './executors/ping.js';
import * as tracerouteExec from './executors/traceroute.js';

// Registry mapping playbook 'uses' strings to executor functions
const registry = {
  'dns.resolve': dnsExec.resolveDNS,
  'whois.lookup': whoisExec.lookupWhois,
  'nmap.scan': nmapExec.scanNmap,
  'http.headers': httpExec.getHeaders,
  'http.get': httpExec.getPath,
  'tls.inspect': tlsExec.inspectTLS,
  'subdomains.passive': subsExec.passive,
  'network.ping': pingExec.ping,
  'network.traceroute': tracerouteExec.traceroute
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
  const outputs = [];
  const startedAt = new Date().toISOString();
  const title = fm.title || fm.id || path.basename(playbookPath);

  for (const [i, step] of steps.entries()) {
    const stepCtx = deepTemplate(step, { ...ctx, content, fm });
    const fn = registry[stepCtx.uses];
    if (!fn) {
      outputs.push({ name: stepCtx.name, uses: stepCtx.uses, error: `Unknown executor` });
      continue;
    }
    logStep(i + 1, stepCtx.name, stepCtx.uses);
    try {
      const effTimeout = stepCtx.with?.timeoutMs ?? stepTimeoutMs;
      const execPromise = fn(ctx.vars.target, stepCtx.with || {});
      const res = await withTimeout(execPromise, effTimeout, stepCtx.name);
      outputs.push({ name: stepCtx.name, uses: stepCtx.uses, ok: true, data: res });
    } catch (e) {
      outputs.push({ name: stepCtx.name, uses: stepCtx.uses, ok: false, error: String(e?.message || e) });
    }
  }

  const endedAt = new Date().toISOString();
  const report = { playbook: { id: fm.id, title, path: playbookPath }, vars: ctx.vars, startedAt, endedAt, outputs };

  const base = timestampFile(title.replace(/\s+/g, '_'));
  const jsonPath = path.join(outDir, `${base}.json`);
  await fs.writeFile(jsonPath, JSON.stringify(report, null, 2));

  // Build Markdown report
  const mdParts = [
    `# ${title}`,
    `- Target: **${ctx.vars.target}**`,
    `- Started: ${startedAt}`,
    `- Ended: ${endedAt}`,
    '',
    '## Steps & Results'
  ];
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

  return { jsonPath, mdPath, report };
}
