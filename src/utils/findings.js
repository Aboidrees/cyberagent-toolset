/**
 * Shared findings model.
 *
 * Normalises the heterogeneous executor outputs (each executor returns its own
 * shape) into a single flat list of severity-rated findings. Reused by the
 * report builder, webhook notifications, and diff reports so they all agree on
 * what counts as a "finding" and how severe it is.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0, none: -1, unknown: 0 };

/** Normalise an arbitrary severity string to one of SEVERITIES. */
export function normalizeSeverity(s) {
  if (!s) return 'info';
  const x = String(s).toLowerCase();
  if (SEVERITIES.includes(x)) return x;
  if (x === 'critical') return 'critical';
  return 'info';
}

/** Numeric rank for sorting / threshold comparisons (higher = worse). */
export function severityRank(s) {
  return SEV_RANK[String(s).toLowerCase()] ?? 0;
}

/**
 * Extract a flat, severity-sorted findings list from a run report's outputs.
 * Understands the per-executor shapes that carry security signal.
 */
export function extractFindings(report) {
  const findings = [];
  const push = (step, uses, severity, message) =>
    findings.push({ step, uses, severity: normalizeSeverity(severity), message });

  for (const o of report?.outputs || []) {
    if (!o || !o.ok || !o.data) continue;
    const d = o.data;

    // Generic findings arrays: email.security, tls.deep, http.cors_check, http.methods, ip.intel
    if (Array.isArray(d.findings)) {
      for (const f of d.findings) {
        push(o.name, o.uses, f.severity, f.message || f.check || JSON.stringify(f));
      }
    }

    switch (o.uses) {
      case 'vuln.cve_lookup':
        for (const c of d.results || []) {
          push(o.name, o.uses, c.severity, `${c.id} (CVSS ${c.cvss}) — ${(c.description || '').slice(0, 140)}`);
        }
        break;
      case 'http.git_leak':
        if (d.exposed) push(o.name, o.uses, 'critical', d.note || 'Exposed .git directory');
        break;
      case 'cloud.bucket_finder':
        for (const b of d.exposed || []) {
          push(o.name, o.uses, b.severity, `Public bucket: ${b.url} (${b.access})`);
        }
        break;
      case 'http.security_score':
        if (['D', 'E', 'F'].includes(d.grade)) {
          push(o.name, o.uses, d.grade === 'F' ? 'high' : 'medium', `Security header grade ${d.grade} (${d.score}%)`);
        }
        for (const leak of d.infoLeaks || []) push(o.name, o.uses, 'low', leak);
        break;
      case 'shodan.host':
        for (const v of d.vulns || []) push(o.name, o.uses, 'high', `Shodan-reported CVE: ${v}`);
        break;
      default:
        break;
    }
  }

  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  return findings;
}

/** Count findings per severity bucket. */
export function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) if (counts[f.severity] !== undefined) counts[f.severity]++;
  return counts;
}

/** Highest severity present, or null if there are no findings. */
export function topSeverity(findings) {
  return findings.reduce((top, f) =>
    severityRank(f.severity) > severityRank(top) ? f.severity : top, 'info');
}
