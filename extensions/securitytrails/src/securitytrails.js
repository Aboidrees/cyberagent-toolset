import axios from 'axios';
import { validateTarget } from '#sdk';

const BASE = 'https://api.securitytrails.com/v1';

function key(opts) {
  return opts.apiKey || process.env.SECURITYTRAILS_API_KEY;
}

async function call(pathname, apiKey, timeoutMs) {
  const res = await axios.get(`${BASE}${pathname}`, {
    headers: { APIKEY: apiKey, Accept: 'application/json' },
    timeout: timeoutMs || 15000,
    validateStatus: () => true,
    maxContentLength: 10_000_000,
  });
  return res;
}

/**
 * Historical subdomains from SecurityTrails (passive DNS dataset). Key-gated:
 * no-op note unless SECURITYTRAILS_API_KEY (or opts.apiKey) is set.
 */
export async function subdomains(target, opts = {}) {
  const domain = validateTarget(target);
  const apiKey = key(opts);
  if (!apiKey) return { target: domain, checked: false, note: 'Skipped — set SECURITYTRAILS_API_KEY to enable.' };

  const res = await call(`/domain/${domain}/subdomains?children_only=false`, apiKey, opts.timeoutMs);
  if (res.status === 429) return { target: domain, checked: false, note: 'SecurityTrails rate limit hit.' };
  if (res.status !== 200) return { target: domain, checked: false, note: `SecurityTrails returned HTTP ${res.status}.` };

  const subs = (res.data?.subdomains || []).map(s => `${s}.${domain}`).sort();
  return { target: domain, checked: true, count: subs.length, subdomains: subs };
}

/**
 * Historical A-record (passive DNS) timeline from SecurityTrails. Key-gated.
 */
export async function dnsHistory(target, opts = {}) {
  const domain = validateTarget(target);
  const apiKey = key(opts);
  if (!apiKey) return { target: domain, checked: false, note: 'Skipped — set SECURITYTRAILS_API_KEY to enable.' };

  const res = await call(`/history/${domain}/dns/a`, apiKey, opts.timeoutMs);
  if (res.status !== 200) return { target: domain, checked: false, note: `SecurityTrails returned HTTP ${res.status}.` };

  const records = (res.data?.records || []).slice(0, 50).map(r => ({
    firstSeen: r.first_seen, lastSeen: r.last_seen,
    ips: (r.values || []).map(v => v.ip),
  }));
  return { target: domain, checked: true, count: records.length, history: records };
}
