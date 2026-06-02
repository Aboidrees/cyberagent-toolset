import dns from 'dns/promises';
import axios from 'axios';
import { validateTarget } from '#sdk';

const IPV4_PLAIN_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// Rough hosting-type heuristics from the AS name / org string.
const CLOUD_HINTS = [
  { re: /amazon|aws/i,        provider: 'AWS',           type: 'cloud' },
  { re: /google/i,            provider: 'Google Cloud',  type: 'cloud' },
  { re: /microsoft|azure/i,   provider: 'Azure',         type: 'cloud' },
  { re: /cloudflare/i,        provider: 'Cloudflare',    type: 'cdn' },
  { re: /akamai/i,            provider: 'Akamai',        type: 'cdn' },
  { re: /fastly/i,            provider: 'Fastly',        type: 'cdn' },
  { re: /digitalocean/i,      provider: 'DigitalOcean',  type: 'cloud' },
  { re: /linode/i,            provider: 'Linode',        type: 'cloud' },
  { re: /hetzner/i,           provider: 'Hetzner',       type: 'cloud' },
  { re: /ovh/i,               provider: 'OVH',           type: 'cloud' },
  { re: /oracle/i,            provider: 'Oracle Cloud',  type: 'cloud' },
];

/**
 * Resolve the target to a single IPv4 address. Hostnames are A-resolved.
 */
async function resolveIpv4(target, explicitIp) {
  if (explicitIp) {
    const clean = validateTarget(explicitIp);
    if (!IPV4_PLAIN_RE.test(clean)) {
      throw new Error(`opts.ip must be a plain IPv4 address, got "${clean}"`);
    }
    return clean;
  }
  if (IPV4_PLAIN_RE.test(target)) return target;
  const addrs = await dns.resolve4(target);
  if (!addrs.length) throw new Error(`Could not resolve an IPv4 address for ${target}`);
  return addrs[0];
}

/**
 * Look up ASN/BGP/country data for an IPv4 address via Team Cymru's
 * keyless DNS-based IP-to-ASN service.
 */
async function cymruLookup(ip) {
  const reversed = ip.split('.').reverse().join('.');

  let originTxt;
  try {
    const recs = await dns.resolveTxt(`${reversed}.origin.asn.cymru.com`);
    originTxt = recs.map(c => c.join('')).join(' ');
  } catch {
    return { available: false, note: 'No Team Cymru origin record (IP may be private/unannounced).' };
  }

  // Format: "ASN | BGP Prefix | CC | Registry | Allocated"
  const [asnRaw, prefix, cc, registry, allocated] = originTxt.split('|').map(s => s.trim());

  // The ASN is derived from an untrusted DNS TXT response and is interpolated
  // into a follow-up DNS query below — only accept a purely numeric value so a
  // malformed/hostile record can't redirect that lookup to an arbitrary name.
  const asn = /^\d+$/.test(asnRaw || '') ? asnRaw : null;

  const out = {
    available: true,
    asn,
    bgpPrefix: prefix || null,
    country: cc || null,
    registry: registry || null,
    allocated: allocated || null,
    asName: null,
  };

  // Second lookup resolves the AS number to a human-readable org name.
  if (asn) {
    try {
      const nameRecs = await dns.resolveTxt(`AS${asn}.asn.cymru.com`);
      const nameTxt = nameRecs.map(c => c.join('')).join(' ');
      // Format: "ASN | CC | Registry | Allocated | AS Name"
      out.asName = (nameTxt.split('|').pop() || '').trim() || null;
    } catch {
      // name lookup is best-effort
    }
  }

  return out;
}

/**
 * Classify the hosting provider/type from the AS name.
 */
function classifyHosting(asName) {
  if (!asName) return { provider: null, type: 'unknown' };
  for (const hint of CLOUD_HINTS) {
    if (hint.re.test(asName)) return { provider: hint.provider, type: hint.type };
  }
  return { provider: asName, type: 'on-prem/other' };
}

/**
 * Optional AbuseIPDB reputation enrichment. Only runs when an API key is
 * supplied via opts.apiKey or the ABUSEIPDB_API_KEY environment variable —
 * otherwise it is skipped with a note (no key shipped with this tool).
 */
async function abuseReputation(ip, opts) {
  const apiKey = opts.apiKey || process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return { checked: false, note: 'Skipped — set ABUSEIPDB_API_KEY to enable abuse-reputation scoring.' };
  }
  try {
    const res = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: apiKey, Accept: 'application/json' },
      timeout: opts.timeoutMs || 8000,
      validateStatus: () => true,
    });
    if (res.status !== 200) {
      return { checked: false, note: `AbuseIPDB returned HTTP ${res.status}.` };
    }
    const d = res.data?.data || {};
    return {
      checked: true,
      abuseConfidenceScore: d.abuseConfidenceScore,
      totalReports: d.totalReports,
      isWhitelisted: d.isWhitelisted,
      lastReportedAt: d.lastReportedAt,
      usageType: d.usageType,
      isp: d.isp,
    };
  } catch (e) {
    return { checked: false, note: `AbuseIPDB lookup failed: ${e.message}` };
  }
}

/**
 * ASN / IP intelligence. Enriches a target IP (or hostname's resolved IP)
 * with ASN, BGP prefix, country, registry, and hosting-provider classification
 * via Team Cymru's keyless service. Abuse reputation is an optional, key-gated
 * add-on that stays disabled unless an AbuseIPDB key is provided.
 */
export async function intel(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const ip = await resolveIpv4(cleanTarget, opts.ip);

  const asn = await cymruLookup(ip);
  const hosting = classifyHosting(asn.asName);
  const reputation = await abuseReputation(ip, opts);

  return {
    target: cleanTarget,
    ip,
    asn,
    hosting,
    reputation,
  };
}
