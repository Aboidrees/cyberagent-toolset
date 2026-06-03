import dns from 'dns/promises';
import axios from 'axios';
import { validateTarget } from '#sdk';

// A small, high-signal built-in subdomain wordlist (keyless brute-force).
const DEFAULT_SUBS = [
  'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp',
  'secure', 'vpn', 'admin', 'portal', 'api', 'dev', 'staging', 'test', 'app',
  'gitlab', 'git', 'jenkins', 'jira', 'confluence', 'docs', 'status', 'cdn',
  'static', 'assets', 'img', 'media', 'shop', 'store', 'm', 'mobile', 'beta',
  'demo', 'cloud', 'proxy', 'gateway', 'auth', 'sso', 'login', 'dashboard',
  'internal', 'intranet', 'corp', 'db', 'sql', 'mysql', 'ftp', 'sftp', 'ssh',
];

/**
 * DNSSEC posture via DNS-over-HTTPS (Cloudflare). Checks for DNSKEY/DS records
 * and the AD (Authenticated Data) flag. Keyless.
 */
export async function dnssec(target, opts = {}) {
  const domain = validateTarget(target);
  const timeoutMs = opts.timeoutMs || 8000;

  async function doh(type) {
    try {
      const res = await axios.get('https://cloudflare-dns.com/dns-query', {
        params: { name: domain, type, do: true },
        headers: { accept: 'application/dns-json' },
        timeout: timeoutMs, validateStatus: () => true, maxContentLength: 1_000_000,
      });
      return res.status === 200 ? res.data : null;
    } catch { return null; }
  }

  const [dnskey, ds] = await Promise.all([doh('DNSKEY'), doh('DS')]);
  const hasDnskey = (dnskey?.Answer || []).some(a => a.type === 48);
  const hasDs = (ds?.Answer || []).some(a => a.type === 43);
  const authenticated = Boolean(dnskey?.AD || ds?.AD);
  const enabled = hasDnskey && (hasDs || authenticated);

  const findings = [];
  if (!enabled) {
    findings.push({ severity: 'low', message: 'DNSSEC is not enabled — DNS responses are not cryptographically signed.' });
  }
  return { target: domain, enabled, hasDnskey, hasDs, authenticated, findings };
}

/**
 * CAA records — which CAs are authorized to issue certificates for the domain.
 * Missing CAA means any CA can issue. Keyless (Node resolver).
 */
export async function caa(target, opts = {}) {
  const domain = validateTarget(target);
  let records = [];
  try {
    records = await dns.resolveCaa(domain);
  } catch {
    records = [];
  }
  const issuers = records.map(r => r.issue || r.issuewild).filter(Boolean);
  const findings = [];
  if (!records.length) {
    findings.push({ severity: 'low', message: 'No CAA record — any certificate authority can issue certs for this domain.' });
  }
  return { target: domain, records, issuers, findings };
}

/**
 * Active subdomain brute-force — resolves a wordlist of candidate subdomains.
 * Concurrency-bounded. Authorized targets only (queries DNS, not the host).
 */
export async function bruteforce(target, opts = {}) {
  const domain = validateTarget(target);
  const words = Array.isArray(opts.wordlist) ? opts.wordlist : DEFAULT_SUBS;
  const concurrency = Math.min(opts.concurrency || 20, 64);
  const timeoutMs = opts.lookupTimeoutMs || 3000;

  const found = [];
  async function probe(sub) {
    const fqdn = `${sub}.${domain}`;
    const lookup = dns.resolve4(fqdn).catch(() => dns.resolve6(fqdn)).catch(() => null);
    const timeout = new Promise(r => { const t = setTimeout(() => r(null), timeoutMs); t.unref?.(); });
    const addrs = await Promise.race([lookup, timeout]);
    if (addrs && addrs.length) found.push({ subdomain: fqdn, addresses: addrs });
  }
  for (let i = 0; i < words.length; i += concurrency) {
    await Promise.all(words.slice(i, i + concurrency).map(probe));
  }
  found.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
  return { target: domain, wordsTried: words.length, found: found.length, subdomains: found };
}
