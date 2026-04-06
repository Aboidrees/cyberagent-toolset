import axios from 'axios';
import { validateTarget } from '../utils/validate.js';

/**
 * Query crt.sh certificate transparency logs for known subdomains.
 */
async function fromCrtSh(domain, timeoutMs = 20000) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  const res = await axios.get(url, { timeout: timeoutMs });

  const names = new Set();
  for (const row of res.data || []) {
    const entries = String(row?.name_value || '').split('\n');
    for (const entry of entries) {
      const cleaned = entry.trim().toLowerCase();
      // Only keep subdomains that genuinely belong to the target domain
      if (cleaned.endsWith(`.${domain}`) || cleaned === domain) {
        names.add(cleaned);
      }
    }
  }

  return Array.from(names).sort();
}

/**
 * Passively enumerate subdomains using certificate transparency logs.
 * No active probing — safe to use at the start of any recon session.
 */
export async function passive(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const sources     = opts.sources || ['crtsh'];
  const timeoutMs   = opts.timeoutMs || 20000;
  const out         = {};

  if (sources.includes('crtsh')) {
    try {
      out.crtsh = await fromCrtSh(cleanTarget, timeoutMs);
    } catch (e) {
      out.crtsh = { error: e.message || String(e) };
    }
  }

  // Merge all source arrays into one deduplicated sorted list
  const merged = Array.from(
    new Set(
      [].concat(
        ...Object.values(out).map(v => (Array.isArray(v) ? v : []))
      )
    )
  ).sort();

  return { merged, sources: out };
}
