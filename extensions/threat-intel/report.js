/**
 * Findings extraction owned by the threat-intel extension.
 * Called by the core aggregator with a single step output { name, uses, data }.
 */
export function findings(output) {
  const out = [];
  const d = output.data || {};

  if (output.uses === 'vuln.cve_lookup') {
    for (const c of d.results || []) {
      out.push({
        severity: c.severity,
        message: `${c.id} (CVSS ${c.cvss}) — ${(c.description || '').slice(0, 140)}`,
      });
    }
  }

  if (output.uses === 'shodan.host') {
    for (const v of d.vulns || []) {
      out.push({ severity: 'high', message: `Shodan-reported CVE: ${v}` });
    }
  }

  return out;
}
