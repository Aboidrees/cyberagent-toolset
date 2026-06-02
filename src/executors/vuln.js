import axios from 'axios';

const NVD_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

/**
 * Pull the best-available CVSS score/severity/vector from an NVD metrics block.
 * Prefers CVSS v3.1, then v3.0, then v2.
 */
function extractCvss(metrics = {}) {
  const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
  const v2 = metrics.cvssMetricV2?.[0];
  if (v31) return { version: '3.1', score: v31.baseScore, severity: v31.baseSeverity, vector: v31.vectorString };
  if (v30) return { version: '3.0', score: v30.baseScore, severity: v30.baseSeverity, vector: v30.vectorString };
  if (v2) {
    return {
      version: '2.0',
      score: v2.cvssData?.baseScore,
      severity: v2.baseSeverity || null,
      vector: v2.cvssData?.vectorString,
    };
  }
  return { version: null, score: null, severity: null, vector: null };
}

/**
 * Map a CVSS base score to a severity bucket when NVD doesn't supply one.
 */
function severityFromScore(score) {
  if (score == null) return 'UNKNOWN';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}

/**
 * CVE lookup against the National Vulnerability Database (NVD API v2).
 *
 * Accepts one of:
 *   - opts.cpe      — a CPE 2.3 name (exact match, e.g. "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
 *   - opts.keyword  — free-text search (e.g. "Apache 2.4.49")
 *   - opts.product + opts.version — combined into a keyword search
 *
 * Keyless by default (NVD public API). Set NVD_API_KEY (or opts.apiKey) to raise
 * the rate limit. Returns matched CVEs with CVSS score, severity, and summary,
 * filtered by opts.minCvss and sorted by score descending.
 *
 * Note: the first positional argument (target) is unused — CVEs are matched by
 * product/version, not host — but kept for executor-signature consistency.
 */
export async function cveLookup(_target, opts = {}) {
  const apiKey = opts.apiKey || process.env.NVD_API_KEY;
  const minCvss = opts.minCvss ?? 0;
  const maxResults = Math.min(opts.maxResults || 20, 100);
  const timeoutMs = opts.timeoutMs || 20000;

  const params = { resultsPerPage: maxResults };
  let query;
  if (opts.cpe) {
    params.cpeName = opts.cpe;
    query = `cpe:${opts.cpe}`;
  } else {
    const keyword = opts.keyword || [opts.product, opts.version].filter(Boolean).join(' ');
    if (!keyword) {
      throw new Error('cve_lookup requires one of: cpe, keyword, or product (+ optional version)');
    }
    params.keywordSearch = keyword;
    query = keyword;
  }
  if (opts.severity) params.cvssV3Severity = String(opts.severity).toUpperCase();

  const headers = { Accept: 'application/json' };
  if (apiKey) headers.apiKey = apiKey;

  const res = await axios.get(NVD_ENDPOINT, {
    params,
    headers,
    timeout: timeoutMs,
    validateStatus: () => true,
    maxContentLength: 10_000_000,
    maxBodyLength: 10_000_000,
  });

  if (res.status === 403 || res.status === 429) {
    return {
      query,
      rateLimited: true,
      note: 'NVD rate limit hit. Set NVD_API_KEY to raise the limit, or retry in ~30s.',
      results: [],
    };
  }
  if (res.status !== 200) {
    return { query, error: `NVD returned HTTP ${res.status}`, results: [] };
  }

  const vulns = res.data?.vulnerabilities || [];
  const results = vulns
    .map(v => {
      const cve = v.cve || {};
      const cvss = extractCvss(cve.metrics);
      const description = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';
      return {
        id: cve.id,
        cvss: cvss.score,
        cvssVersion: cvss.version,
        severity: cvss.severity || severityFromScore(cvss.score),
        vector: cvss.vector,
        published: cve.published,
        description: description.slice(0, 400),
        url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      };
    })
    .filter(r => (r.cvss ?? 0) >= minCvss)
    .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const r of results) if (counts[r.severity] !== undefined) counts[r.severity]++;

  return {
    query,
    totalMatched: res.data?.totalResults ?? results.length,
    returned: results.length,
    minCvss,
    severityCounts: counts,
    usedApiKey: Boolean(apiKey),
    results,
  };
}
