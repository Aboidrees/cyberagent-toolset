import dns from 'dns/promises';
import axios from 'axios';
import { validateTarget } from '#sdk';

const IPV4_PLAIN_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Resolve a target to a single IPv4 address (Shodan indexes by IP).
 */
async function resolveIpv4(target) {
  if (IPV4_PLAIN_RE.test(target)) return target;
  const addrs = await dns.resolve4(target);
  if (!addrs.length) throw new Error(`Could not resolve an IPv4 address for ${target}`);
  return addrs[0];
}

/**
 * Shodan host lookup — open ports, services, banners, CVEs, and tags from
 * Shodan's internet-wide index.
 *
 * Requires a Shodan API key, supplied via opts.apiKey or the SHODAN_API_KEY
 * environment variable. When no key is present the executor is a no-op that
 * returns a note (no key ships with this tool), so it can sit in a playbook
 * without failing the run.
 */
export async function hostLookup(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const apiKey = opts.apiKey || process.env.SHODAN_API_KEY;

  if (!apiKey) {
    return {
      target: cleanTarget,
      checked: false,
      note: 'Skipped — set SHODAN_API_KEY (or pass apiKey) to enable Shodan host lookups.',
    };
  }

  let ip;
  try {
    ip = await resolveIpv4(cleanTarget);
  } catch (e) {
    // Mirror the other failure paths with a structured note rather than throwing.
    return { target: cleanTarget, checked: false, note: `Could not resolve an IPv4 address: ${e.message}` };
  }

  const res = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
    params: { key: apiKey },
    timeout: opts.timeoutMs || 15000,
    validateStatus: () => true,
    maxContentLength: 10_000_000,
    maxBodyLength: 10_000_000,
  });

  if (res.status === 401) {
    return { target: cleanTarget, ip, checked: false, note: 'Shodan rejected the API key (HTTP 401).' };
  }
  if (res.status === 404) {
    return { target: cleanTarget, ip, checked: true, found: false, note: 'No Shodan data for this IP.' };
  }
  if (res.status !== 200) {
    return { target: cleanTarget, ip, checked: false, note: `Shodan returned HTTP ${res.status}.` };
  }

  const d = res.data || {};
  return {
    target: cleanTarget,
    ip,
    checked: true,
    found: true,
    org: d.org || null,
    isp: d.isp || null,
    os: d.os || null,
    country: d.country_name || null,
    ports: d.ports || [],
    hostnames: d.hostnames || [],
    tags: d.tags || [],
    vulns: d.vulns || [],
    services: (d.data || []).slice(0, 25).map(s => ({
      port: s.port,
      transport: s.transport,
      product: s.product || null,
      version: s.version || null,
      banner: typeof s.data === 'string' ? s.data.slice(0, 300) : null,
    })),
    lastUpdate: d.last_update || null,
  };
}
