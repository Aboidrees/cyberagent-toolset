import axios from 'axios';

/**
 * EPSS scoring — the Exploit Prediction Scoring System (FIRST.org) estimates the
 * probability a CVE will be exploited in the wild in the next 30 days. Use it to
 * prioritise the CVEs from `vuln.cve_lookup` by real-world risk, not just CVSS.
 *
 * Keyless. Takes CVE id(s) via opts.cve (string, comma list, or array). The first
 * positional arg (target) is unused — EPSS is keyed by CVE, not host.
 */
export async function epss(_target, opts = {}) {
  const raw = opts.cve || opts.cves;
  const ids = (Array.isArray(raw) ? raw : String(raw || '').split(','))
    .map(s => s.trim().toUpperCase())
    .filter(s => /^CVE-\d{4}-\d{4,}$/.test(s));

  if (!ids.length) {
    return { error: 'vuln.epss requires one or more CVE ids via opts.cve (e.g. "CVE-2021-44228").', results: [] };
  }

  const minScore = opts.minScore ?? 0;
  const res = await axios.get('https://api.first.org/data/v1/epss', {
    params: { cve: ids.join(','), pretty: false },
    timeout: opts.timeoutMs || 15000,
    validateStatus: () => true,
    maxContentLength: 5_000_000,
  });

  if (res.status !== 200 || !res.data) {
    return { query: ids, error: `EPSS API returned HTTP ${res.status}`, results: [] };
  }

  const results = (res.data.data || [])
    .map(r => ({
      cve: r.cve,
      epss: Number(r.epss),                 // 0..1 probability of exploitation
      percentile: Number(r.percentile),     // 0..1 rank vs all CVEs
      date: r.date,
    }))
    .filter(r => r.epss >= minScore)
    .sort((a, b) => b.epss - a.epss);

  // High EPSS = likely to be exploited soon → worth flagging.
  const findings = results
    .filter(r => r.epss >= (opts.findingThreshold ?? 0.5))
    .map(r => ({
      severity: r.epss >= 0.9 ? 'high' : 'medium',
      message: `${r.cve} EPSS ${(r.epss * 100).toFixed(1)}% (top ${(100 - r.percentile * 100).toFixed(1)}%) — likely to be exploited`,
    }));

  return { query: ids, returned: results.length, results, findings };
}
