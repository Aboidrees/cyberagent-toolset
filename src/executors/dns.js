import dns from 'dns/promises';
import { validateTarget } from '../utils/validate.js';

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
