/**
 * Shared findings model.
 *
 * Normalises heterogeneous executor outputs into one flat, severity-rated list.
 * Generic `data.findings[]` handling lives here; domain-specific extraction is
 * owned by each extension's `report.findings(stepOutput)` and delegated to via
 * the `reportersByUses` map (built by the extension loader). This keeps the core
 * thin and lets third-party extensions emit findings without patching it.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0, none: -1, unknown: 0 };

/** Normalise an arbitrary severity string to one of SEVERITIES. */
export function normalizeSeverity(s) {
  if (!s) return 'info';
  const x = String(s).toLowerCase();
  return SEVERITIES.includes(x) ? x : 'info';
}

/** Numeric rank for sorting / threshold comparisons (higher = worse). */
export function severityRank(s) {
  return SEV_RANK[String(s).toLowerCase()] ?? 0;
}

/**
 * Extract a flat, severity-sorted findings list from a run report's outputs.
 *
 * @param report             a run report ({ outputs: [...] })
 * @param reportersByUses    optional `uses` → { findings(stepOutput) } map from
 *                           the extension catalog. When omitted, only generic
 *                           `data.findings[]` arrays are collected.
 */
export function extractFindings(report, reportersByUses = {}) {
  const findings = [];
  const push = (step, uses, severity, message) =>
    findings.push({ step, uses, severity: normalizeSeverity(severity), message });

  for (const o of report?.outputs || []) {
    if (!o || !o.ok || !o.data) continue;

    // Generic: any executor may return a `findings: [{severity, message}]` array.
    if (Array.isArray(o.data.findings)) {
      for (const f of o.data.findings) {
        push(o.name, o.uses, f.severity, f.message || f.check || JSON.stringify(f));
      }
    }

    // Domain-specific: delegate to the owning extension's report module.
    const reporter = reportersByUses[o.uses];
    if (reporter && typeof reporter.findings === 'function') {
      try {
        for (const f of reporter.findings(o) || []) {
          push(o.name, o.uses, f.severity, f.message);
        }
      } catch {
        // a misbehaving extension reporter must not break the run report
      }
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

/** Highest severity present, or 'info' if there are no findings. */
export function topSeverity(findings) {
  return findings.reduce((top, f) =>
    severityRank(f.severity) > severityRank(top) ? f.severity : top, 'info');
}
