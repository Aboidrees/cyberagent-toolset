import axios from 'axios';
import { validateTarget } from '../utils/validate.js';

/**
 * Build a URL from scheme, host, and path.
 *
 * `host` is already sanitised by validateTarget. `scheme` and `path` are
 * caller-supplied, so they are constrained here to prevent the request from
 * being re-pointed away from the validated host (scheme smuggling / `@`-based
 * host override): scheme is whitelisted to http/https, and the path may not
 * contain credentials, whitespace, backslashes, or a protocol-relative prefix.
 */
function buildUrl(scheme, host, urlPath = '/') {
  const safeScheme = scheme === 'http' ? 'http' : 'https';
  const p = urlPath || '/';
  // eslint-disable-next-line no-control-regex
  if (/[@\\\s]/.test(p) || /[\x00-\x1f]/.test(p) || p.startsWith('//')) {
    throw new Error(
      `Invalid path "${p}": must be a host-relative path without credentials, ` +
      `whitespace, backslashes, or a protocol-relative ("//") prefix.`
    );
  }
  const normalised = p.startsWith('/') ? p : `/${p}`;
  return `${safeScheme}://${host}${normalised}`;
}

/**
 * Retrieve HTTP response headers for a given path.
 * Returns { url, status, headers }.
 */
export async function getHeaders(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', cleanTarget, opts.path || '/');

  const res = await axios.get(url, {
    timeout: opts.timeoutMs || 10000,
    validateStatus: () => true,   // never throw on HTTP error codes
    maxRedirects: 5,
    maxContentLength: 5_000_000,
    maxBodyLength: 5_000_000,
  });

  return { url, status: res.status, headers: res.headers };
}

/**
 * Perform a GET request and return status, headers, and a body snippet.
 * Body is truncated to 5000 chars to avoid overwhelming the caller.
 */
export async function getPath(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', cleanTarget, opts.path || '/');

  const res = await axios.get(url, {
    timeout: opts.timeoutMs || 10000,
    validateStatus: () => true,
    maxRedirects: 5,
    maxContentLength: 5_000_000,
    maxBodyLength: 5_000_000,
  });

  const snippet =
    typeof res.data === 'string' ? res.data.slice(0, 5000) : res.data;

  return { url, status: res.status, headers: res.headers, bodySnippet: snippet };
}

// ─────────────────────────────────────────────────────────────────────────────
// http.security_score — A–F grade of security-relevant response headers
// ─────────────────────────────────────────────────────────────────────────────

// Each header carries a weight; some have a validator that grants partial credit.
const SECURITY_HEADERS = [
  { name: 'strict-transport-security', weight: 20, label: 'Strict-Transport-Security (HSTS)',
    advice: 'Add HSTS with a long max-age and includeSubDomains.' },
  { name: 'content-security-policy', weight: 25, label: 'Content-Security-Policy',
    advice: 'Define a CSP to mitigate XSS and data injection.' },
  { name: 'x-frame-options', weight: 10, label: 'X-Frame-Options',
    advice: 'Set X-Frame-Options: DENY/SAMEORIGIN (or CSP frame-ancestors) to prevent clickjacking.' },
  { name: 'x-content-type-options', weight: 10, label: 'X-Content-Type-Options',
    advice: 'Set X-Content-Type-Options: nosniff to stop MIME sniffing.' },
  { name: 'referrer-policy', weight: 10, label: 'Referrer-Policy',
    advice: 'Set a Referrer-Policy such as strict-origin-when-cross-origin.' },
  { name: 'permissions-policy', weight: 10, label: 'Permissions-Policy',
    advice: 'Restrict powerful browser features with a Permissions-Policy.' },
  { name: 'cross-origin-opener-policy', weight: 5, label: 'Cross-Origin-Opener-Policy',
    advice: 'Add Cross-Origin-Opener-Policy: same-origin for cross-origin isolation.' },
  { name: 'cross-origin-resource-policy', weight: 5, label: 'Cross-Origin-Resource-Policy',
    advice: 'Add Cross-Origin-Resource-Policy to limit resource sharing.' },
  { name: 'cross-origin-embedder-policy', weight: 5, label: 'Cross-Origin-Embedder-Policy',
    advice: 'Add Cross-Origin-Embedder-Policy: require-corp where applicable.' },
];

function scoreToGrade(pct) {
  if (pct >= 90) return 'A';
  if (pct >= 75) return 'B';
  if (pct >= 60) return 'C';
  if (pct >= 45) return 'D';
  if (pct >= 25) return 'E';
  return 'F';
}

/**
 * Score the security-relevant response headers and return an A–F grade
 * with per-header presence, value, and remediation advice.
 */
export async function securityScore(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', cleanTarget, opts.path || '/');

  const res = await axios.get(url, {
    timeout: opts.timeoutMs || 10000,
    validateStatus: () => true,
    maxRedirects: 5,
    maxContentLength: 5_000_000,
    maxBodyLength: 5_000_000,
  });

  const headers = res.headers || {};
  const totalWeight = SECURITY_HEADERS.reduce((s, h) => s + h.weight, 0);
  let earned = 0;
  const details = [];
  const missing = [];

  for (const h of SECURITY_HEADERS) {
    const value = headers[h.name];
    const present = value !== undefined;
    if (present) earned += h.weight;
    else missing.push(h.label);
    details.push({ header: h.label, present, value: present ? value : null, weight: h.weight, advice: present ? null : h.advice });
  }

  // An "info leak" penalty for verbose Server / X-Powered-By banners.
  const leaks = [];
  if (headers['server'] && /\d/.test(headers['server'])) leaks.push(`Server banner reveals version: ${headers['server']}`);
  if (headers['x-powered-by']) leaks.push(`X-Powered-By disclosed: ${headers['x-powered-by']}`);

  const pct = Math.round((earned / totalWeight) * 100);
  const grade = scoreToGrade(pct);

  return {
    url,
    status: res.status,
    grade,
    score: pct,
    earned,
    maxScore: totalWeight,
    presentCount: SECURITY_HEADERS.length - missing.length,
    missing,
    infoLeaks: leaks,
    details,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// http.waf_detect — WAF / CDN fingerprint from headers, cookies, and banners
// ─────────────────────────────────────────────────────────────────────────────

const WAF_SIGNATURES = [
  { name: 'Cloudflare',          type: 'waf/cdn', headers: ['cf-ray', 'cf-cache-status'], server: /cloudflare/i, cookie: /__cfduid|__cf_bm/i },
  { name: 'AWS WAF / CloudFront', type: 'waf/cdn', headers: ['x-amz-cf-id', 'x-amzn-requestid', 'x-amz-cf-pop'], server: /cloudfront|awselb/i },
  { name: 'Akamai',              type: 'cdn',     headers: ['x-akamai-transformed', 'akamai-grn'], server: /akamai/i },
  { name: 'Imperva / Incapsula', type: 'waf',     headers: ['x-iinfo', 'x-cdn'], cookie: /incap_ses|visid_incap/i },
  { name: 'Sucuri',              type: 'waf',     headers: ['x-sucuri-id', 'x-sucuri-cache'], server: /sucuri/i },
  { name: 'F5 BIG-IP',           type: 'waf',     cookie: /BIGipServer|TS[0-9a-f]{8}/, server: /big-?ip/i },
  { name: 'Fastly',              type: 'cdn',     headers: ['x-served-by', 'x-fastly-request-id'], server: /fastly/i },
  { name: 'Varnish',             type: 'cache',   headers: ['x-varnish', 'via'], via: /varnish/i },
  { name: 'Azure Front Door',    type: 'waf/cdn', headers: ['x-azure-ref'], server: /azure/i },
  { name: 'Barracuda',           type: 'waf',     cookie: /barra_counter_session/i },
  { name: 'Wordfence',           type: 'waf',     cookie: /wordfence_verifiedHuman/i },
];

/**
 * Detect WAF / CDN presence from response headers, cookies, and server banner.
 */
export async function wafDetect(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', cleanTarget, opts.path || '/');

  const res = await axios.get(url, {
    timeout: opts.timeoutMs || 10000,
    validateStatus: () => true,
    maxRedirects: 5,
    maxContentLength: 5_000_000,
    maxBodyLength: 5_000_000,
  });

  const headers = res.headers || {};
  const server = String(headers['server'] || '');
  const via = String(headers['via'] || '');
  const setCookie = []
    .concat(headers['set-cookie'] || [])
    .join('; ');

  const detected = [];
  for (const sig of WAF_SIGNATURES) {
    const evidence = [];
    for (const h of sig.headers || []) {
      if (headers[h] !== undefined) evidence.push(`header:${h}`);
    }
    if (sig.server && sig.server.test(server)) evidence.push(`server:${server}`);
    if (sig.via && sig.via.test(via)) evidence.push(`via:${via}`);
    if (sig.cookie && sig.cookie.test(setCookie)) evidence.push('cookie-match');
    if (evidence.length) detected.push({ name: sig.name, type: sig.type, evidence });
  }

  return {
    url,
    status: res.status,
    wafDetected: detected.length > 0,
    detected,
    server: server || null,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// http.fingerprint — technology stack from headers and body markers
// ─────────────────────────────────────────────────────────────────────────────

const TECH_SIGNATURES = [
  // Servers
  { category: 'server',     name: 'nginx',         header: 'server',       re: /nginx/i },
  { category: 'server',     name: 'Apache',        header: 'server',       re: /apache/i },
  { category: 'server',     name: 'Microsoft IIS', header: 'server',       re: /iis|microsoft-httpapi/i },
  { category: 'server',     name: 'LiteSpeed',     header: 'server',       re: /litespeed/i },
  { category: 'server',     name: 'Caddy',         header: 'server',       re: /caddy/i },
  // Languages / frameworks via X-Powered-By
  { category: 'language',   name: 'PHP',           header: 'x-powered-by', re: /php/i },
  { category: 'framework',  name: 'ASP.NET',       header: 'x-powered-by', re: /asp\.net/i },
  { category: 'framework',  name: 'Express',       header: 'x-powered-by', re: /express/i },
  { category: 'framework',  name: 'Next.js',       header: 'x-powered-by', re: /next\.js/i },
  // Frameworks via dedicated headers
  { category: 'framework',  name: 'Laravel',       header: 'set-cookie',   re: /laravel_session/i },
  { category: 'framework',  name: 'Django',        header: 'set-cookie',   re: /csrftoken|sessionid/i },
  { category: 'framework',  name: 'Rails',         header: 'set-cookie',   re: /_session_id/i },
  { category: 'framework',  name: 'Next.js',       header: 'x-nextjs-cache', re: /.*/ },
  { category: 'cms',        name: 'WordPress',     header: 'link',         re: /wp-json/i },
];

// Body markers (HTML) — matched against the response body.
const BODY_SIGNATURES = [
  { category: 'cms',        name: 'WordPress',     re: /wp-content|wp-includes/i },
  { category: 'cms',        name: 'Drupal',        re: /sites\/(all|default)\/|drupal\.js/i },
  { category: 'cms',        name: 'Joomla',        re: /\/media\/jui\/|joomla/i },
  { category: 'framework',  name: 'React',         re: /data-reactroot|__REACT_DEVTOOLS/i },
  { category: 'framework',  name: 'Vue.js',        re: /data-v-[0-9a-f]{8}|__vue__/i },
  { category: 'framework',  name: 'Angular',       re: /ng-version|ng-app/i },
  { category: 'framework',  name: 'Next.js',       re: /__NEXT_DATA__/i },
  { category: 'framework',  name: 'Nuxt',          re: /__NUXT__/i },
  { category: 'analytics',  name: 'Google Analytics', re: /google-analytics\.com|gtag\(/i },
  { category: 'analytics',  name: 'Google Tag Manager', re: /googletagmanager\.com/i },
  { category: 'library',    name: 'jQuery',        re: /jquery[.-]/i },
  { category: 'library',    name: 'Bootstrap',     re: /bootstrap(\.min)?\.(css|js)/i },
];

/**
 * Fingerprint the technology stack from response headers and (optionally) body.
 */
export async function fingerprint(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', cleanTarget, opts.path || '/');

  const res = await axios.get(url, {
    timeout: opts.timeoutMs || 10000,
    validateStatus: () => true,
    maxRedirects: 5,
    maxContentLength: 5_000_000,
    maxBodyLength: 5_000_000,
  });

  const headers = res.headers || {};
  const tech = [];
  const seen = new Set();
  const add = (sig, source, value) => {
    const key = `${sig.category}:${sig.name}`;
    if (seen.has(key)) return;
    seen.add(key);
    tech.push({ category: sig.category, name: sig.name, source, evidence: value });
  };

  for (const sig of TECH_SIGNATURES) {
    const raw = headers[sig.header];
    const val = Array.isArray(raw) ? raw.join('; ') : raw;
    if (val !== undefined && sig.re.test(String(val))) add(sig, `header:${sig.header}`, String(val).slice(0, 120));
  }

  // Deep mode also inspects the HTML body for client-side framework markers.
  if (opts.deep !== false && typeof res.data === 'string') {
    const body = res.data;
    for (const sig of BODY_SIGNATURES) {
      if (sig.re.test(body)) add(sig, 'body', sig.name);
    }
    const generator = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
    if (generator) add({ category: 'cms', name: generator[1] }, 'meta:generator', generator[1]);
  }

  return {
    url,
    status: res.status,
    server: headers['server'] || null,
    poweredBy: headers['x-powered-by'] || null,
    technologies: tech,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// http.fuzz_paths — active path enumeration with built-in wordlists
// ─────────────────────────────────────────────────────────────────────────────

const WORDLISTS = {
  common: [
    '/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/favicon.ico',
    '/admin/', '/login', '/dashboard', '/config', '/backup', '/backup.zip',
    '/.env', '/.git/config', '/test', '/dev', '/old', '/tmp', '/uploads/',
    '/api', '/status', '/health', '/server-status', '/phpinfo.php', '/info.php',
  ],
  api: [
    '/api', '/api/v1', '/api/v2', '/api/docs', '/api/swagger', '/swagger.json',
    '/openapi.json', '/graphql', '/graphiql', '/api/health', '/api/status',
    '/api/users', '/api/admin', '/v1', '/v2', '/.well-known/openid-configuration',
  ],
  admin: [
    '/admin/', '/admin/login', '/administrator/', '/wp-admin/', '/manage/',
    '/management/', '/cpanel/', '/phpmyadmin/', '/adminer.php', '/console/',
    '/dashboard/', '/portal/', '/staff/', '/backend/',
  ],
  php: [
    '/index.php', '/info.php', '/phpinfo.php', '/config.php', '/config.inc.php',
    '/wp-config.php.bak', '/db.php', '/install.php', '/setup.php', '/test.php',
    '/shell.php', '/upload.php', '/adminer.php',
  ],
  asp: [
    '/default.aspx', '/web.config', '/trace.axd', '/elmah.axd', '/admin.aspx',
    '/login.aspx', '/api.asmx', '/service.svc', '/global.asax',
  ],
};

/**
 * Active path enumeration. Probes a built-in (or custom) wordlist against the
 * target and reports which paths exist by status code. Concurrency-bounded.
 *
 * Active — only run against authorized targets.
 */
export async function fuzzPaths(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const scheme = opts.scheme || 'https';
  // Per-request timeout is separate from any step-level budget the runner applies
  // via `timeoutMs` — this executor fires many requests, so a single shared value
  // would make the whole step exceed its own per-request cap.
  const reqTimeoutMs = opts.requestTimeoutMs || 5000;
  const concurrency = Math.min(opts.threads || 10, 32);

  const list = Array.isArray(opts.wordlist)
    ? opts.wordlist
    : WORDLISTS[opts.wordlist || 'common'] || WORDLISTS.common;

  const hits = [];
  async function probe(path) {
    const url = buildUrl(scheme, cleanTarget, path);
    try {
      const res = await axios.get(url, {
        timeout: reqTimeoutMs,
        validateStatus: () => true,
        maxRedirects: 0,
        maxContentLength: 2_000_000,
        maxBodyLength: 2_000_000,
      });
      // Treat anything that isn't a hard 404 / connection error as "present".
      if (res.status !== 404) {
        const len = res.headers?.['content-length'] ||
          (typeof res.data === 'string' ? res.data.length : null);
        hits.push({ path, status: res.status, contentLength: len ? Number(len) : null });
      }
    } catch {
      // connection refused / timeout → treat as not present
    }
  }

  for (let i = 0; i < list.length; i += concurrency) {
    await Promise.all(list.slice(i, i + concurrency).map(probe));
  }

  hits.sort((a, b) => a.status - b.status || a.path.localeCompare(b.path));
  return {
    target: cleanTarget,
    wordlist: Array.isArray(opts.wordlist) ? 'custom' : (opts.wordlist || 'common'),
    pathsTried: list.length,
    found: hits.length,
    hits,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// http.git_leak — exposed .git directory detector
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Git repository leak detector. Checks for an exposed `.git/` directory and
 * pulls indicators (remote origin URL, last commit message) when accessible.
 * Flags as critical when repository internals are reachable.
 */
export async function gitLeak(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const scheme = opts.scheme || 'https';
  const timeoutMs = opts.timeoutMs || 8000;

  async function get(path) {
    try {
      const res = await axios.get(buildUrl(scheme, cleanTarget, path), {
        timeout: timeoutMs,
        validateStatus: () => true,
        maxRedirects: 0,
        maxContentLength: 2_000_000,
        maxBodyLength: 2_000_000,
      });
      return { status: res.status, body: typeof res.data === 'string' ? res.data : '' };
    } catch (e) {
      return { status: 0, body: '', error: e.message };
    }
  }

  const head = await get('/.git/HEAD');
  // A real .git/HEAD looks like "ref: refs/heads/main" — a 200 with HTML is just
  // a catch-all page, not an exposed repo.
  const headLooksReal = head.status === 200 && /^ref:\s|^[0-9a-f]{40}/m.test(head.body);

  const result = {
    target: cleanTarget,
    exposed: headLooksReal,
    checks: { '/.git/HEAD': head.status },
  };

  if (!headLooksReal) {
    result.severity = 'none';
    result.note = head.status === 200
      ? '/.git/HEAD returned 200 but content is not a real git ref (likely a catch-all page).'
      : 'No exposed .git directory detected.';
    return result;
  }

  // Repo is exposed — pull the high-value indicator files.
  const [config, commitMsg] = await Promise.all([
    get('/.git/config'),
    get('/.git/COMMIT_EDITMSG'),
  ]);
  result.checks['/.git/config'] = config.status;
  result.checks['/.git/COMMIT_EDITMSG'] = commitMsg.status;

  const indicators = {};
  if (config.status === 200 && config.body) {
    indicators.head = head.body.trim().slice(0, 200);
    const remote = config.body.match(/url\s*=\s*(.+)/);
    if (remote) indicators.remoteOrigin = remote[1].trim();
  }
  if (commitMsg.status === 200 && commitMsg.body) {
    indicators.lastCommitMessage = commitMsg.body.trim().slice(0, 200);
  }

  result.severity = 'critical';
  result.indicators = indicators;
  result.note = 'Exposed .git directory — source code and history may be reconstructable.';
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// http.cors_check — CORS misconfiguration probe
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Probe for CORS misconfigurations. Sends a request with a hostile Origin and
 * inspects the Access-Control-Allow-Origin / -Credentials response headers.
 * Flags origin reflection and the dangerous wildcard-plus-credentials combo.
 */
export async function corsCheck(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', cleanTarget, opts.path || '/');
  const evilOrigin = opts.origin || 'https://evil.example.com';

  const res = await axios.get(url, {
    timeout: opts.timeoutMs || 10000,
    validateStatus: () => true,
    maxRedirects: 2,
    maxContentLength: 2_000_000,
    maxBodyLength: 2_000_000,
    headers: { Origin: evilOrigin },
  });

  const headers = res.headers || {};
  const acao = headers['access-control-allow-origin'] || null;
  const acac = headers['access-control-allow-credentials'] || null;
  const findings = [];

  if (acao === evilOrigin) {
    findings.push({
      severity: acac === 'true' ? 'high' : 'medium',
      message: acac === 'true'
        ? 'Origin is reflected AND credentials are allowed — any site can read authenticated responses.'
        : 'Arbitrary Origin is reflected in Access-Control-Allow-Origin.',
    });
  } else if (acao === '*' && acac === 'true') {
    findings.push({ severity: 'high', message: 'Wildcard origin with credentials allowed (browsers block this, but it signals misconfig).' });
  } else if (acao === 'null') {
    findings.push({ severity: 'medium', message: 'Access-Control-Allow-Origin: null — exploitable from sandboxed iframes.' });
  }

  return {
    url,
    status: res.status,
    testedOrigin: evilOrigin,
    allowOrigin: acao,
    allowCredentials: acac,
    reflectsOrigin: acao === evilOrigin,
    misconfigured: findings.length > 0,
    findings,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// http.methods — allowed HTTP methods + risky-method probe
// ─────────────────────────────────────────────────────────────────────────────

// CONNECT is intentionally excluded: Node's HTTP client treats it as a tunnel
// request (emits a 'connect' event, never a 'response'), so axios's timeout
// never fires and the probe hangs. It isn't meaningful for auditing a normal
// web server anyway.
const RISKY_METHODS = ['PUT', 'DELETE', 'TRACE', 'PATCH'];

/**
 * Enumerate allowed HTTP methods via OPTIONS (Allow header) and actively probe
 * for risky methods (PUT/DELETE/TRACE/etc.) that the server actually accepts.
 */
export async function methods(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const scheme = opts.scheme || 'https';
  const url = buildUrl(scheme, cleanTarget, opts.path || '/');
  // Per-request timeout, independent of the runner's step-level budget — this
  // executor fires OPTIONS plus one probe per risky method.
  const reqTimeoutMs = opts.requestTimeoutMs || 6000;

  const out = { url, advertised: [], riskyAccepted: [], findings: [] };

  const request = (method) => axios.request({
    url, method,
    timeout: reqTimeoutMs, validateStatus: () => true, maxRedirects: 0,
    maxContentLength: 1_000_000, maxBodyLength: 1_000_000,
  });

  // Fire OPTIONS and every risky-method probe concurrently so the whole audit
  // costs ~one round trip rather than one per method.
  const [optionsRes, ...riskyRes] = await Promise.all([
    request('OPTIONS').then(r => r, e => ({ error: e })),
    ...RISKY_METHODS.map(m => request(m).then(r => ({ method: m, status: r.status }), () => null)),
  ]);

  if (optionsRes.error) {
    out.optionsError = optionsRes.error.message;
  } else {
    out.optionsStatus = optionsRes.status;
    const allow = optionsRes.headers?.['allow'];
    if (allow) out.advertised = allow.split(',').map(m => m.trim().toUpperCase()).filter(Boolean);
  }

  // A non-405/501/404/400 response means the method is actually handled.
  out.riskyAccepted = riskyRes.filter(r => r && ![405, 501, 404, 400].includes(r.status));

  if (out.advertised.includes('TRACE') || out.riskyAccepted.some(r => r.method === 'TRACE')) {
    out.findings.push({ severity: 'medium', message: 'TRACE is enabled — can enable Cross-Site Tracing (XST).' });
  }
  for (const r of out.riskyAccepted) {
    if (r.method === 'PUT' || r.method === 'DELETE') {
      out.findings.push({ severity: 'high', message: `${r.method} appears accepted (HTTP ${r.status}) — verify it cannot modify content.` });
    }
  }

  return out;
}
