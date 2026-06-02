import axios from 'axios';
import { validateTarget } from '#sdk';

/**
 * GitHub code search for references to the target domain — surfaces public code
 * that mentions the domain (configs, hardcoded hosts, potential leaks).
 *
 * Key-gated: GitHub code search requires authentication. No-op note unless
 * GITHUB_TOKEN (or opts.token) is set. ⚠️ Review matches manually — a mention is
 * not proof of a leak.
 */
export async function leaks(target, opts = {}) {
  const domain = validateTarget(target);
  const token = opts.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (!token) {
    return { target: domain, checked: false, note: 'Skipped — set GITHUB_TOKEN to enable GitHub code search.' };
  }

  const query = opts.query || `"${domain}"`;
  const res = await axios.get('https://api.github.com/search/code', {
    params: { q: query, per_page: Math.min(opts.maxResults || 30, 100) },
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github.text-match+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'cyberagent-toolset',
    },
    timeout: opts.timeoutMs || 15000,
    validateStatus: () => true,
    maxContentLength: 10_000_000,
  });

  if (res.status === 401 || res.status === 403) {
    return { target: domain, checked: false, note: `GitHub rejected the token or rate-limited (HTTP ${res.status}).` };
  }
  if (res.status !== 200) {
    return { target: domain, checked: false, note: `GitHub returned HTTP ${res.status}.` };
  }

  const items = (res.data?.items || []).map(it => ({
    repo: it.repository?.full_name,
    path: it.path,
    url: it.html_url,
  }));
  const findings = items.slice(0, 20).map(it => ({
    severity: 'low',
    message: `Domain referenced in public code: ${it.repo}/${it.path}`,
  }));

  return { target: domain, checked: true, totalCount: res.data?.total_count ?? items.length, returned: items.length, items, findings };
}
