/**
 * Assessment synthesis — turn an accumulated session into a prioritized report.
 *
 * This is the deliverable the agent hands back: a correlated, ranked view of the
 * whole investigation rather than per-tool dumps. Findings are deduped and
 * severity-sorted; CVEs are correlated with their EPSS exploit-probability so the
 * "top risks" reflect real-world likelihood, not just CVSS; entities are
 * inventoried by type.
 */

import { severityRank, severityCounts } from './utils/findings.js';

const ENTITY_ORDER = ['domain', 'subdomain', 'ip', 'port', 'url', 'tech', 'cve', 'email', 'nameserver', 'mailhost', 'service'];

/** Build the structured synthesis + a Markdown rendering. */
export function synthesize(session) {
  const byType = {};
  for (const e of session.entities) (byType[e.type] ||= []).push(e);

  const counts = severityCounts(session.findings);
  const top = session.findings.find(Boolean)?.severity || 'info';

  // CVE correlation: rank by EPSS (exploit probability), then CVSS.
  const cves = (byType.cve || [])
    .map(e => ({ cve: e.value, epss: e.attrs?.epss ?? null, cvss: e.attrs?.cvss ?? null, severity: e.attrs?.severity ?? null }))
    .sort((a, b) => (b.epss ?? -1) - (a.epss ?? -1) || (b.cvss ?? -1) - (a.cvss ?? -1));

  // "Top risks": critical/high findings first, then high-EPSS CVEs.
  const topRisks = [
    ...session.findings.filter(f => severityRank(f.severity) >= 3),
    ...cves.filter(c => (c.epss ?? 0) >= 0.5).map(c => ({
      severity: (c.epss ?? 0) >= 0.9 ? 'high' : 'medium',
      message: `${c.cve} — EPSS ${(c.epss * 100).toFixed(1)}%${c.cvss ? `, CVSS ${c.cvss}` : ''}`,
      uses: 'vuln.epss', target: session.target,
    })),
  ].slice(0, 25);

  const entityInventory = {};
  for (const t of ENTITY_ORDER) if (byType[t]) entityInventory[t] = byType[t].map(e => e.value);

  const usesRun = [...new Set(session.steps.map(s => s.uses))];

  const json = {
    id: session.id,
    target: session.target,
    targetType: session.targetType,
    status: session.status,
    posture: session.posture,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    coverage: { stepsRun: session.steps.length, executorsUsed: usesRun.length, executors: usesRun.sort() },
    entityCounts: Object.fromEntries(ENTITY_ORDER.filter(t => byType[t]).map(t => [t, byType[t].length])),
    severityCounts: counts,
    topSeverity: top,
    topRisks,
    cves,
    findings: session.findings,
    entities: entityInventory,
  };

  return { json, markdown: render(json) };
}

function render(j) {
  const L = [];
  L.push(`# Assessment — ${j.target}`);
  L.push('');
  L.push(`- **ID:** ${j.id}  ·  **Type:** ${j.targetType}  ·  **Status:** ${j.status}${j.posture ? `  ·  **Posture:** ${j.posture}` : ''}`);
  L.push(`- **Coverage:** ${j.coverage.stepsRun} steps · ${j.coverage.executorsUsed} executors`);
  const sc = j.severityCounts;
  L.push(`- **Findings:** ${sc.critical} critical · ${sc.high} high · ${sc.medium} medium · ${sc.low} low · ${sc.info} info`);
  L.push('');

  if (j.topRisks.length) {
    L.push('## Top risks');
    L.push('');
    for (const r of j.topRisks) L.push(`- **${r.severity.toUpperCase()}** — ${r.message}  _(${r.uses})_`);
    L.push('');
  }

  if (j.cves.length) {
    L.push('## CVEs (by exploit probability)');
    L.push('');
    L.push('| CVE | EPSS | CVSS | Severity |');
    L.push('| --- | ---- | ---- | -------- |');
    for (const c of j.cves.slice(0, 25)) {
      L.push(`| ${c.cve} | ${c.epss != null ? (c.epss * 100).toFixed(1) + '%' : '—'} | ${c.cvss ?? '—'} | ${c.severity ?? '—'} |`);
    }
    L.push('');
  }

  L.push('## Entities discovered');
  L.push('');
  if (Object.keys(j.entities).length) {
    for (const [type, vals] of Object.entries(j.entities)) {
      L.push(`- **${type}** (${vals.length}): ${vals.slice(0, 30).join(', ')}${vals.length > 30 ? ' …' : ''}`);
    }
  } else {
    L.push('_None yet._');
  }
  L.push('');

  if (j.findings.length) {
    L.push('## All findings');
    L.push('');
    for (const f of j.findings) L.push(`- **${f.severity.toUpperCase()}** — ${f.message}  _(${f.uses} · ${f.target})_`);
    L.push('');
  }

  L.push('## Executors run');
  L.push('');
  L.push(j.coverage.executors.join(', ') || '_none_');
  L.push('');
  return L.join('\n');
}
