import whois from 'whois-json';
import { validateTarget } from '../utils/validate.js';

/**
 * Perform a WHOIS lookup for a domain or IP address.
 */
export async function lookupWhois(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const timeout     = opts.timeoutMs || 15000;

  try {
    const data = await whois(cleanTarget, { follow: 2, timeout });
    return data;
  } catch (e) {
    throw new Error(`whois failed for "${cleanTarget}": ${e.message || e}`);
  }
}
