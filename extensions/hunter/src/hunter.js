import axios from 'axios';
import { validateTarget } from '#sdk';

/**
 * Hunter.io domain email harvest. Returns the email addresses, the address
 * pattern, and the organization Hunter.io associates with a domain — useful for
 * mapping an organisation's externally-visible email footprint (and phishing
 * exposure) during authorized assessments.
 *
 * Key-gated: needs a Hunter.io API key (free tier available) via opts.apiKey or
 * HUNTER_API_KEY. Without a key it no-ops with a note, so it can sit in a
 * playbook without failing the run. Passive — queries Hunter.io, not the target.
 *
 * The key is read through the permission-scoped `ctx.env` when available, so the
 * runtime can enforce the extension's declared `permissions.env`.
 */
export async function domainEmails(target, opts = {}, ctx = {}) {
  const domain = validateTarget(target);
  const fromCtx = typeof ctx.env === 'function' ? ctx.env('HUNTER_API_KEY') : process.env.HUNTER_API_KEY;
  const apiKey = opts.apiKey || fromCtx;

  if (!apiKey) {
    return {
      target: domain,
      checked: false,
      note: 'Skipped — set HUNTER_API_KEY (or pass apiKey) to enable Hunter.io email harvesting. Free tier: hunter.io/api-keys.',
    };
  }

  const limit = Math.min(opts.limit || 25, 100);
  let res;
  try {
    res = await axios.get('https://api.hunter.io/v2/domain-search', {
      params: { domain, api_key: apiKey, limit },
      timeout: opts.timeoutMs || 15000,
      validateStatus: () => true,
      maxContentLength: 5_000_000,
    });
  } catch (e) {
    return { target: domain, checked: true, error: `Hunter.io request failed: ${e.message}`, emails: [] };
  }

  if (res.status === 401) return { target: domain, checked: true, error: 'Hunter.io rejected the API key (401).', emails: [] };
  if (res.status !== 200 || !res.data?.data) {
    const msg = res.data?.errors?.[0]?.details || `HTTP ${res.status}`;
    return { target: domain, checked: true, error: `Hunter.io error: ${msg}`, emails: [] };
  }

  const d = res.data.data;
  const emails = (d.emails || []).map(e => ({
    value: e.value,
    type: e.type,                       // personal | generic
    confidence: e.confidence,
    name: [e.first_name, e.last_name].filter(Boolean).join(' ') || null,
    position: e.position || null,
    department: e.department || null,
    sources: Array.isArray(e.sources) ? e.sources.length : 0,
  }));

  const findings = [];
  if (emails.length) {
    findings.push({
      severity: 'info',
      message: `${emails.length} email address(es) discoverable for ${domain} via Hunter.io${d.pattern ? ` (pattern: ${d.pattern})` : ''}`,
    });
  }

  return {
    target: domain,
    checked: true,
    organization: d.organization || null,
    pattern: d.pattern || null,
    disposable: d.disposable ?? null,
    webmail: d.webmail ?? null,
    total: emails.length,
    emails,
    findings,
  };
}
