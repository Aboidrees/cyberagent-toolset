import dns from 'dns/promises';

// Resolve various DNS record types for a given target.
export async function resolveDNS(target, opts = {}) {
  const types = opts.types || ['A', 'AAAA'];
  const out = {};
  for (const t of types) {
    try {
      out[t] = await dns.resolve(target, t);
    } catch {
      out[t] = [];
    }
  }
  // Include SOA record if available (non-fatal on failure)
  try {
    out['SOA'] = await dns.resolveSoa(target);
  } catch {
    // ignore
  }
  return out;
}