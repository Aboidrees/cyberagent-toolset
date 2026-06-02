import dns from 'dns/promises';
import axios from 'axios';
import { validateTarget } from '#sdk';

const IPV4_PLAIN_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

async function resolveIpv4(target) {
  if (IPV4_PLAIN_RE.test(target)) return target;
  const addrs = await dns.resolve4(target);
  if (!addrs.length) throw new Error(`Could not resolve an IPv4 for ${target}`);
  return addrs[0];
}

/**
 * Censys host lookup — services, ports, software, and location for an IP.
 * Key-gated: needs CENSYS_API_ID + CENSYS_API_SECRET (or opts.apiId/apiSecret).
 * No-op note when unset.
 */
export async function host(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const apiId = opts.apiId || process.env.CENSYS_API_ID;
  const apiSecret = opts.apiSecret || process.env.CENSYS_API_SECRET;
  if (!apiId || !apiSecret) {
    return { target: cleanTarget, checked: false, note: 'Skipped — set CENSYS_API_ID and CENSYS_API_SECRET to enable.' };
  }

  let ip;
  try { ip = await resolveIpv4(cleanTarget); }
  catch (e) { return { target: cleanTarget, checked: false, note: e.message }; }

  const res = await axios.get(`https://search.censys.io/api/v2/hosts/${ip}`, {
    auth: { username: apiId, password: apiSecret },
    timeout: opts.timeoutMs || 15000,
    validateStatus: () => true,
    maxContentLength: 10_000_000,
  });
  if (res.status === 401) return { target: cleanTarget, ip, checked: false, note: 'Censys rejected the credentials (401).' };
  if (res.status === 404) return { target: cleanTarget, ip, checked: true, found: false, note: 'No Censys data for this IP.' };
  if (res.status !== 200) return { target: cleanTarget, ip, checked: false, note: `Censys returned HTTP ${res.status}.` };

  const r = res.data?.result || {};
  return {
    target: cleanTarget,
    ip,
    checked: true,
    found: true,
    services: (r.services || []).slice(0, 50).map(s => ({
      port: s.port, transport: s.transport_protocol, service: s.service_name,
      software: (s.software || []).map(sw => sw.product).filter(Boolean),
    })),
    location: r.location ? { country: r.location.country, city: r.location.city } : null,
    autonomousSystem: r.autonomous_system ? { asn: r.autonomous_system.asn, name: r.autonomous_system.name } : null,
    lastUpdated: r.last_updated_at || null,
  };
}
