/**
 * Example executor implementation.
 *
 * The signature is always `run(target, opts, ctx)`:
 *   - target : the validated host/domain/ip/url string from the playbook/CLI.
 *   - opts   : the executor's `with:` block (your options).
 *   - ctx    : shared services injected by the engine. Use these instead of
 *              importing from the host package — that keeps your plugin
 *              decoupled and lets the runtime enforce your declared permissions:
 *                ctx.validateTarget(t)   — same input validation the core uses
 *                ctx.env(KEY)            — read a declared env var (see index.js)
 *                ctx.requireBin(name)    — check a declared external binary
 *                ctx.normalizeSeverity / ctx.severityRank
 *
 * Return any JSON-serialisable object. If you include a `findings: []` array of
 * `{ severity, message }`, the engine rolls those into the report automatically.
 */
export async function example(target, opts = {}, ctx = {}) {
  const host = ctx.validateTarget ? ctx.validateTarget(target) : target;
  const scheme = opts.scheme === 'http' ? 'http' : 'https';
  const url = `${scheme}://${host}/`;

  // Optional API key, read through the permission-scoped accessor.
  const apiKey = opts.apiKey || (ctx.env ? ctx.env('EXAMPLE_API_KEY') : undefined);

  let status = null;
  let title = null;
  try {
    const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(opts.timeoutMs || 10000) });
    status = res.status;
    const body = await res.text();
    title = (body.match(/<title[^>]*>([^<]*)<\/title>/i) || [])[1]?.trim() || null;
  } catch (e) {
    return { target: host, url, error: e.message, findings: [] };
  }

  const findings = [];
  if (status && status >= 500) {
    findings.push({ severity: 'low', message: `Server returned ${status} for ${url}` });
  }

  return { target: host, url, status, title, authenticated: Boolean(apiKey), findings };
}
