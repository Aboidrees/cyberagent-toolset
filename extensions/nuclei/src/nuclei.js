import { execFile } from 'child_process';
import { promisify } from 'util';
import { validateTarget, isCommandAvailable } from '#sdk';

const pexecFile = promisify(execFile);

/**
 * Nuclei template scan — runs the `nuclei` binary against the target and returns
 * structured findings. Nuclei ships thousands of community templates (CVEs,
 * exposures, misconfigurations, default creds, takeovers), so this one executor
 * multiplies coverage enormously.
 *
 * Degrades gracefully: if the `nuclei` binary isn't installed, it returns a
 * no-op note rather than failing the run. Install:
 *   https://github.com/projectdiscovery/nuclei
 *
 * ⚠️ Active — only run against authorized targets.
 */
export async function scan(target, opts = {}) {
  const host = validateTarget(target);

  if (!(await isCommandAvailable('nuclei'))) {
    return {
      target: host,
      checked: false,
      note: 'Skipped — install the `nuclei` binary (github.com/projectdiscovery/nuclei) to enable thousands of templated checks.',
    };
  }

  const scheme = opts.scheme || 'https';
  const url = `${scheme}://${host}`;
  const severity = Array.isArray(opts.severity) ? opts.severity.join(',')
    : (opts.severity || 'critical,high,medium');

  // execFile (no shell) — args are an array, target is validated.
  const args = [
    '-target', url,
    '-jsonl', '-silent', '-no-color',
    '-severity', severity,
    '-timeout', String(opts.requestTimeoutSec || 10),
    '-rate-limit', String(opts.rateLimit || 50),
  ];
  if (opts.tags) args.push('-tags', Array.isArray(opts.tags) ? opts.tags.join(',') : opts.tags);
  if (opts.templates) args.push('-t', ...(Array.isArray(opts.templates) ? opts.templates : [opts.templates]));

  let stdout = '';
  try {
    const r = await pexecFile('nuclei', args, { timeout: opts.timeoutMs || 600000, maxBuffer: 32 * 1024 * 1024 });
    stdout = r.stdout || '';
  } catch (e) {
    // nuclei can exit non-zero while still producing results on stdout.
    stdout = e.stdout || '';
    if (!stdout) return { target: host, url, checked: true, found: 0, results: [], error: e.message };
  }

  const results = stdout.split('\n').filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean)
    .map(j => ({
      id: j['template-id'] || j.templateID || null,
      name: j.info?.name || null,
      severity: (j.info?.severity || 'info').toLowerCase(),
      matchedAt: j['matched-at'] || j.matched_at || j.host || url,
      type: j.type || null,
    }));

  return { target: host, url, checked: true, found: results.length, results };
}
