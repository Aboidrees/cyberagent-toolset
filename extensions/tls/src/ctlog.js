import axios from 'axios';
import { validateTarget } from '#sdk';

/**
 * Certificate Transparency history via crt.sh. CT logs are an append-only public
 * record of every certificate a CA issues, so they reveal a domain's certificate
 * timeline, every issuing CA, and (often) internal/forgotten subdomain names —
 * all passively, without touching the target. Keyless.
 *
 * Returns an aggregate summary plus the most recent certificates. Set
 * opts.includeSubdomains to also return the unique SAN/CN names observed.
 */
export async function ctlog(target, opts = {}) {
  const domain = validateTarget(target);
  const limit = Math.min(opts.limit || 50, 500);

  let res;
  try {
    res = await axios.get('https://crt.sh/', {
      params: { q: `%.${domain}`, output: 'json' },
      timeout: opts.timeoutMs || 30000,
      validateStatus: () => true,
      maxContentLength: 30_000_000,
      headers: { 'User-Agent': 'cyberagent-toolset' },
    });
  } catch (e) {
    return { target: domain, error: `crt.sh request failed: ${e.message}`, certificates: [] };
  }

  if (res.status !== 200 || !Array.isArray(res.data)) {
    return { target: domain, error: `crt.sh returned HTTP ${res.status}`, certificates: [] };
  }

  const rows = res.data;
  const issuers = new Map();
  const names = new Set();
  let earliest = null;
  let latest = null;

  for (const r of rows) {
    const issuer = (r.issuer_name || '').replace(/\s+/g, ' ').trim();
    if (issuer) issuers.set(issuer, (issuers.get(issuer) || 0) + 1);
    for (const n of String(r.name_value || '').split(/\n/)) {
      const name = n.trim().toLowerCase();
      if (name) names.add(name);
    }
    const nb = Date.parse(r.not_before);
    const na = Date.parse(r.not_after);
    if (!Number.isNaN(nb) && (earliest === null || nb < earliest)) earliest = nb;
    if (!Number.isNaN(na) && (latest === null || na > latest)) latest = na;
  }

  // Most recent certs first (by not_before), trimmed to `limit`.
  const certificates = rows
    .slice()
    .sort((a, b) => (Date.parse(b.not_before) || 0) - (Date.parse(a.not_before) || 0))
    .slice(0, limit)
    .map(r => ({
      id: r.id,
      commonName: r.common_name,
      issuer: (r.issuer_name || '').replace(/\s+/g, ' ').trim(),
      notBefore: r.not_before,
      notAfter: r.not_after,
      serial: r.serial_number,
    }));

  const topIssuers = [...issuers.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ issuer: name, count }));

  const findings = [];
  // Many distinct issuers can indicate shadow IT / inconsistent CA governance.
  if (topIssuers.length >= 5) {
    findings.push({
      severity: 'info',
      message: `${topIssuers.length} distinct certificate issuers seen for ${domain}`,
    });
  }

  const result = {
    target: domain,
    totalCertificates: rows.length,
    uniqueNames: names.size,
    issuers: topIssuers,
    firstSeen: earliest ? new Date(earliest).toISOString().slice(0, 10) : null,
    lastExpiry: latest ? new Date(latest).toISOString().slice(0, 10) : null,
    certificates,
    findings,
  };
  if (opts.includeSubdomains) {
    result.names = [...names].sort();
  }
  return result;
}
