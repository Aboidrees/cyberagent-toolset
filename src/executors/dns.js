import dns from 'dns/promises';
import { validateTarget } from '../utils/validate.js';

// Matches a bare IPv4 address (no CIDR suffix).
const IPV4_PLAIN_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
// Matches an IPv4 CIDR range, e.g. "192.168.1.0/24".
const IPV4_CIDR_RE  = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/;

/**
 * Resolve one or more DNS record types for a target domain.
 * Always validates the target before any network call.
 */
export async function resolveDNS(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const types = opts.types || ['A', 'AAAA'];
  const out = {};

  for (const t of types) {
    try {
      out[t] = await dns.resolve(cleanTarget, t);
    } catch {
      out[t] = [];
    }
  }

  // SOA is a special call — non-fatal on failure
  if (!types.includes('SOA')) {
    try {
      out['SOA'] = await dns.resolveSoa(cleanTarget);
    } catch {
      // ignore — not all domains have SOA accessible
    }
  }

  return out;
}

/**
 * Expand an IPv4 CIDR range into a list of host addresses.
 * Refuses ranges larger than `maxHosts` to keep PTR sweeps bounded.
 */
function expandCidr(cidr, maxHosts) {
  const [, base, prefixStr] = cidr.match(IPV4_CIDR_RE);
  const prefix = parseInt(prefixStr, 10);
  if (prefix < 0 || prefix > 32) {
    throw new Error(`Invalid CIDR prefix /${prefixStr}`);
  }

  const octets = base.split('.').map(n => parseInt(n, 10));
  const baseInt = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const hostBits = 32 - prefix;
  const size = hostBits >= 32 ? 2 ** 32 : 2 ** hostBits;

  if (size > maxHosts) {
    throw new Error(
      `CIDR ${cidr} expands to ${size} addresses, exceeding the limit of ${maxHosts}. ` +
      `Use a smaller range (e.g. /24 or tighter).`
    );
  }

  const networkInt = (baseInt & (size > 1 ? ~(size - 1) : 0xffffffff)) >>> 0;
  const ips = [];
  for (let i = 0; i < size; i++) {
    const ip = (networkInt + i) >>> 0;
    ips.push(`${(ip >>> 24) & 255}.${(ip >>> 16) & 255}.${(ip >>> 8) & 255}.${ip & 255}`);
  }
  return ips;
}

/**
 * Reverse DNS (PTR) lookup for a target. Accepts:
 *   - a single IPv4/IPv6 address  → one PTR lookup
 *   - an IPv4 CIDR range          → PTR sweep across every host in the range
 *   - a hostname                  → resolves A/AAAA first, then PTR each IP
 *
 * Returns a per-IP map of resolved PTR names plus a flat, deduplicated list.
 */
export async function reverseDNS(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const maxHosts = opts.maxHosts || 256;

  // Determine the set of IPs to look up.
  let ips = [];
  let resolvedFrom = 'ip';

  if (IPV4_CIDR_RE.test(cleanTarget)) {
    resolvedFrom = 'cidr';
    ips = expandCidr(cleanTarget, maxHosts);
  } else if (IPV4_PLAIN_RE.test(cleanTarget) || cleanTarget.includes(':')) {
    // Bare IPv4 or IPv6 literal.
    ips = [cleanTarget];
  } else {
    // Hostname — resolve forward records first, then reverse each.
    resolvedFrom = 'hostname';
    for (const t of ['A', 'AAAA']) {
      try {
        ips.push(...(await dns.resolve(cleanTarget, t)));
      } catch {
        // ignore — host may not have that record type
      }
    }
    ips = [...new Set(ips)];
  }

  const ptr = {};
  const allNames = new Set();
  // Bound each lookup so one slow/blackholing resolver response can't stall an
  // entire CIDR sweep. Lookups run concurrently in capped batches.
  const lookupTimeoutMs = opts.lookupTimeoutMs || 4000;
  const concurrency = Math.min(opts.concurrency || 16, 64);

  async function reverseOne(ip) {
    const lookup = dns.reverse(ip).catch(() => []);
    const timeout = new Promise(resolve => {
      const t = setTimeout(() => resolve([]), lookupTimeoutMs);
      t.unref?.();
    });
    const names = await Promise.race([lookup, timeout]);
    ptr[ip] = names;
    names.forEach(n => allNames.add(n));
  }

  for (let i = 0; i < ips.length; i += concurrency) {
    await Promise.all(ips.slice(i, i + concurrency).map(reverseOne));
  }

  return {
    target: cleanTarget,
    resolvedFrom,
    ipCount: ips.length,
    ptr,
    names: Array.from(allNames).sort(),
  };
}
