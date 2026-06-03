import fs from 'fs/promises';
import matter from 'gray-matter';
import yaml from 'js-yaml';
import path from 'path';
import { timestampFile } from './utils/fsx.js';
import { logStep } from './utils/logger.js';
import { extractFindings, severityCounts, topSeverity } from './utils/findings.js';
import { notify } from './utils/notify.js';
import { loadCatalog } from './extensions/loader.js';

// The executor registry is built from the extension catalog (local extensions/
// + npm cyberagent-ext-* plugins), not hardcoded here.

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

export async function runPlaybook({ playbookPath, playbook, outDir, varOverrides = {}, stepTimeoutMs, posture }) {
  // Source the playbook from an in-memory object (e.g. the `auto` command) or
  // load it. `.yaml`/`.yml` are pure YAML; `.md` is YAML front matter + Markdown
  // body (legacy). The body, when present, is exposed to templates.
  let fm, content = '';
  if (playbook) {
    fm = playbook;
  } else if (playbookPath.endsWith('.yaml') || playbookPath.endsWith('.yml')) {
    fm = yaml.load(await fs.readFile(playbookPath, 'utf8')) || {};
  } else {
    const parsed = matter(await fs.readFile(playbookPath, 'utf8'), { engines: { yaml: s => yaml.load(s) } });
    fm = parsed.data;
    content = parsed.content;
  }

  const catalog = await loadCatalog();
  const metaByUses = new Map(catalog.executors.map(e => [e.uses, e]));
  const ctx = { vars: { ...(fm.vars || {}), ...varOverrides } };
  const steps = fm.steps || [];
  const outputs = new Array(steps.length);
  const startedAt = new Date().toISOString();
  const title = fm.title || fm.id || (playbookPath ? path.basename(playbookPath) : 'run');

  // Execute one step and return its output object (caller controls ordering).
  const runStep = async (step, i) => {
    // `env` is exposed so playbooks can reference keys, e.g.
    // `apiKey: "{{env.SHODAN_API_KEY}}"`.
    const stepCtx = deepTemplate(step, { ...ctx, env: process.env, content, fm });
    const fn = catalog.registry[stepCtx.uses];
    if (!fn) {
      return { name: stepCtx.name, uses: stepCtx.uses, error: `Unknown executor` };
    }
    // Passive-only / safe mode: skip any active executor (no packets to the host).
    if (posture === 'passive') {
      const meta = metaByUses.get(stepCtx.uses);
      if (meta && meta.posture !== 'passive') {
        logStep(i + 1, `${stepCtx.name} (skipped — active)`, stepCtx.uses);
        return { name: stepCtx.name, uses: stepCtx.uses, skipped: true, reason: 'passive-only mode: executor is active' };
      }
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
  const findings = extractFindings(report, catalog.reportersByUses);
  const counts = severityCounts(findings);

  // Annotate outputs + findings with their executor's phase/posture/domain, and
  // compute per-phase coverage (for the phase-grouped report views).
  for (const o of outputs) {
    const m = metaByUses.get(o.uses);
    if (m) { o.phase = m.phase; o.posture = m.posture; o.domain = m.domain; }
  }
  for (const f of findings) {
    const m = metaByUses.get(f.uses);
    if (m) f.phase = m.phase;
  }
  const phaseCoverage = {};
  for (const o of outputs) {
    const ph = o.phase || 'other';
    const c = (phaseCoverage[ph] ||= { ran: 0, skipped: 0, failed: 0 });
    if (o.skipped) c.skipped++; else if (o.ok) c.ran++; else c.failed++;
  }

  report.findings = findings;
  report.severityCounts = counts;
  report.topSeverity = findings.length ? topSeverity(findings) : null;
  report.phaseCoverage = phaseCoverage;

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
    '**Coverage by phase:** ' + (['reconnaissance', 'scanning', 'gaining-access']
      .filter(ph => phaseCoverage[ph])
      .map(ph => {
        const c = phaseCoverage[ph];
        const extra = [c.skipped ? `${c.skipped} skipped` : '', c.failed ? `${c.failed} failed` : ''].filter(Boolean).join(', ');
        return `${ph} ${c.ran}${extra ? ` (${extra})` : ''}`;
      }).join(' · ') || 'none'),
    '',
  ];
  if (findings.length) {
    mdParts.push('### Findings by phase', '');
    const byPhase = {};
    for (const f of findings) (byPhase[f.phase || 'other'] ||= []).push(f);
    for (const ph of ['reconnaissance', 'scanning', 'gaining-access', 'other']) {
      const list = byPhase[ph];
      if (!list || !list.length) continue;
      mdParts.push(`**${ph}** (${list.length})`, '');
      for (const f of list.slice(0, 50)) {
        mdParts.push(`- **[${f.severity.toUpperCase()}]** ${f.message} — \`${f.uses}\` (${f.step})`);
      }
      mdParts.push('');
    }
  }
  mdParts.push('## Steps & Results');
  for (const o of outputs) {
    mdParts.push(`### ${o.name} \`(${o.uses})\``);
    if (o.skipped) {
      mdParts.push(`⏭️ **Skipped**: ${o.reason}`);
    } else if (o.ok) {
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
