import dns from 'dns/promises';
import axios from 'axios';
import { validateTarget } from '#sdk';
import { buildUrl } from './http.js';

const GET = (url, opts = {}) => axios.get(url, {
  timeout: opts.timeoutMs || 10000,
  validateStatus: () => true,
  maxRedirects: opts.maxRedirects ?? 0,
  maxContentLength: 3_000_000,
  maxBodyLength: 3_000_000,
  headers: opts.headers,
});

// ── web.wayback ──────────────────────────────────────────────────────────────
/**
 * Archived URLs from the Wayback Machine (web.archive.org CDX API). Passive —
 * queries the archive, not the target. Useful for discovering old endpoints.
 */
export async function wayback(target, opts = {}) {
  const domain = validateTarget(target);
  const limit = Math.min(opts.limit || 200, 2000);
  try {
    const res = await axios.get('https://web.archive.org/cdx/search/cdx', {
      params: { url: `${domain}/*`, output: 'json', fl: 'original', collapse: 'urlkey', limit },
      timeout: opts.timeoutMs || 20000, validateStatus: () => true, maxContentLength: 10_000_000,
    });
    const rows = Array.isArray(res.data) ? res.data.slice(1) : [];
    const urls = [...new Set(rows.map(r => r[0]).filter(Boolean))];
    return { target: domain, found: urls.length, urls };
  } catch (e) {
    return { target: domain, found: 0, urls: [], error: e.message };
  }
}

// ── http.secrets ─────────────────────────────────────────────────────────────
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', re: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'Google API Key', re: /AIza[0-9A-Za-z_-]{35}/g, severity: 'high' },
  { name: 'Slack Token', re: /xox[baprs]-[0-9A-Za-z-]{10,48}/g, severity: 'critical' },
  { name: 'Stripe Secret Key', re: /sk_live_[0-9A-Za-z]{24,}/g, severity: 'critical' },
  { name: 'GitHub Token', re: /gh[pousr]_[0-9A-Za-z]{36,}/g, severity: 'critical' },
  { name: 'JWT', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'medium' },
  { name: 'Private Key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'Generic API key assignment', re: /(?:api[_-]?key|secret|token)["'\s:=]+[0-9A-Za-z_\-]{20,}/gi, severity: 'low' },
];
const redact = s => s.length <= 12 ? s : `${s.slice(0, 6)}…${s.slice(-4)}`;

/**
 * Scan a page body for exposed secrets (API keys, tokens, private keys, JWTs).
 */
export async function secrets(target, opts = {}) {
  const host = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', host, opts.path || '/');
  const res = await GET(url, { timeoutMs: opts.timeoutMs, maxRedirects: 3 });
  const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data || '');
  const matches = [];
  for (const p of SECRET_PATTERNS) {
    const hits = [...new Set((body.match(p.re) || []))].slice(0, 10);
    for (const h of hits) matches.push({ type: p.name, severity: p.severity, sample: redact(h) });
  }
  const findings = matches.map(m => ({ severity: m.severity, message: `Possible ${m.type} exposed in response: ${m.sample}` }));
  return { url, status: res.status, found: matches.length, matches, findings };
}

// ── http.open_redirect ───────────────────────────────────────────────────────
const REDIRECT_PARAMS = ['url', 'redirect', 'redirect_uri', 'next', 'return', 'returnUrl', 'continue', 'dest', 'destination', 'r', 'u'];
const CANARY = 'https://example.org/';

/**
 * Probe common open-redirect parameters — flags when the app 3xx-redirects to an
 * attacker-supplied off-site URL.
 */
export async function openRedirect(target, opts = {}) {
  const host = validateTarget(target);
  const scheme = opts.scheme || 'https';
  const basePath = opts.path || '/';
  const params = opts.params || REDIRECT_PARAMS;
  const vulnerable = [];

  await Promise.all(params.map(async (param) => {
    const sep = basePath.includes('?') ? '&' : '?';
    const url = buildUrl(scheme, host, `${basePath}${sep}${param}=${encodeURIComponent(CANARY)}`);
    try {
      const res = await GET(url, { timeoutMs: opts.timeoutMs || 8000, maxRedirects: 0 });
      const loc = res.headers?.location || '';
      if (res.status >= 300 && res.status < 400 && /^https?:\/\/example\.org/i.test(loc)) {
        vulnerable.push({ param, status: res.status, location: loc });
      }
    } catch { /* ignore */ }
  }));

  const findings = vulnerable.map(v => ({ severity: 'high', message: `Open redirect via "${v.param}" → ${v.location}` }));
  return { target: host, paramsTried: params.length, vulnerable, misconfigured: vulnerable.length > 0, findings };
}

// ── http.subdomain_takeover ──────────────────────────────────────────────────
const TAKEOVER_SIGNS = [
  { service: 'GitHub Pages', cnameRe: /github\.io$/i, bodyRe: /There isn't a GitHub Pages site here/i },
  { service: 'AWS S3', cnameRe: /s3[.-].*amazonaws\.com$/i, bodyRe: /NoSuchBucket|The specified bucket does not exist/i },
  { service: 'Heroku', cnameRe: /herok(uapp|udns)\.com$/i, bodyRe: /No such app|herokucdn\.com\/error/i },
  { service: 'Azure', cnameRe: /(azurewebsites\.net|cloudapp\.net|trafficmanager\.net)$/i, bodyRe: /404 Web Site not found/i },
  { service: 'Fastly', cnameRe: /fastly\.net$/i, bodyRe: /Fastly error: unknown domain/i },
  { service: 'Shopify', cnameRe: /myshopify\.com$/i, bodyRe: /Sorry, this shop is currently unavailable/i },
  { service: 'Surge', cnameRe: /surge\.sh$/i, bodyRe: /project not found/i },
];

/**
 * Detect dangling-CNAME subdomain takeover — resolves the CNAME chain and
 * matches a known service whose page shows an "unclaimed" fingerprint.
 */
export async function subdomainTakeover(target, opts = {}) {
  const host = validateTarget(target);
  let cname = [];
  try { cname = await dns.resolveCname(host); } catch { cname = []; }
  const chain = cname.join(', ');

  let body = '';
  try {
    const res = await GET(buildUrl(opts.scheme || 'https', host, '/'), { timeoutMs: opts.timeoutMs || 10000, maxRedirects: 2 });
    body = typeof res.data === 'string' ? res.data : '';
  } catch { /* host may not serve */ }

  const findings = [];
  let vulnerable = null;
  for (const s of TAKEOVER_SIGNS) {
    const cnameMatch = cname.some(c => s.cnameRe.test(c));
    const bodyMatch = s.bodyRe.test(body);
    if (cnameMatch && bodyMatch) {
      vulnerable = s.service;
      findings.push({ severity: 'high', message: `Possible subdomain takeover (${s.service}) — dangling CNAME ${chain}` });
      break;
    }
  }
  return { target: host, cname: chain || null, vulnerable, takeoverable: Boolean(vulnerable), findings };
}

// ── http.robots ──────────────────────────────────────────────────────────────
/**
 * Parse robots.txt and sitemap.xml to surface endpoints the site itself reveals.
 */
export async function robots(target, opts = {}) {
  const host = validateTarget(target);
  const scheme = opts.scheme || 'https';
  const out = { target: host, disallow: [], sitemaps: [], sitemapUrls: [] };

  const r = await GET(buildUrl(scheme, host, '/robots.txt'), { timeoutMs: opts.timeoutMs, maxRedirects: 2 });
  if (r.status === 200 && typeof r.data === 'string') {
    for (const line of r.data.split('\n')) {
      const m = line.match(/^\s*Disallow:\s*(\S+)/i);
      if (m) out.disallow.push(m[1]);
      const sm = line.match(/^\s*Sitemap:\s*(\S+)/i);
      if (sm) out.sitemaps.push(sm[1]);
    }
  }
  // Fetch the default sitemap if not referenced.
  const sitemapUrl = out.sitemaps[0] || buildUrl(scheme, host, '/sitemap.xml');
  try {
    const s = await axios.get(sitemapUrl, { timeout: opts.timeoutMs || 10000, validateStatus: () => true, maxContentLength: 5_000_000 });
    if (s.status === 200 && typeof s.data === 'string') {
      out.sitemapUrls = [...new Set([...s.data.matchAll(/<loc>([^<]+)<\/loc>/gi)].map(m => m[1]))].slice(0, 500);
    }
  } catch { /* ignore */ }

  out.disallow = [...new Set(out.disallow)];
  return out;
}

// ── http.cookies ─────────────────────────────────────────────────────────────
/**
 * Audit Set-Cookie security flags (Secure, HttpOnly, SameSite).
 */
export async function cookies(target, opts = {}) {
  const host = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', host, opts.path || '/');
  const res = await GET(url, { timeoutMs: opts.timeoutMs, maxRedirects: 3 });
  const setCookies = [].concat(res.headers?.['set-cookie'] || []);
  const findings = [];
  const cookieReport = setCookies.map(c => {
    const name = (c.split('=')[0] || '').trim();
    const secure = /;\s*Secure/i.test(c);
    const httpOnly = /;\s*HttpOnly/i.test(c);
    const sameSite = (c.match(/;\s*SameSite=(\w+)/i) || [])[1] || null;
    if (!secure) findings.push({ severity: 'low', message: `Cookie "${name}" missing Secure flag` });
    if (!httpOnly) findings.push({ severity: 'low', message: `Cookie "${name}" missing HttpOnly flag` });
    if (!sameSite) findings.push({ severity: 'low', message: `Cookie "${name}" missing SameSite attribute` });
    return { name, secure, httpOnly, sameSite };
  });
  return { url, status: res.status, count: cookieReport.length, cookies: cookieReport, findings };
}

// ── http.graphql ─────────────────────────────────────────────────────────────
const INTROSPECTION_QUERY = JSON.stringify({
  query: '{__schema{queryType{name} mutationType{name} types{name kind}}}',
});
const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/graphql/v1', '/query', '/api'];

/**
 * Detect a GraphQL endpoint and whether introspection is exposed — sends the
 * introspection query to common paths and reports any that return a schema.
 * Introspection in production leaks the full API surface.
 */
export async function graphql(target, opts = {}) {
  const host = validateTarget(target);
  const scheme = opts.scheme || 'https';
  const paths = opts.path ? [opts.path] : GRAPHQL_PATHS;
  const endpoints = [];

  for (const p of paths) {
    let url;
    try { url = buildUrl(scheme, host, p); } catch { continue; }
    try {
      const res = await axios.post(url, INTROSPECTION_QUERY, {
        timeout: opts.timeoutMs || 8000,
        validateStatus: () => true,
        maxRedirects: 0,
        maxContentLength: 5_000_000,
        headers: { 'Content-Type': 'application/json' },
      });
      const schema = res.data?.data?.__schema;
      if (schema && Array.isArray(schema.types)) {
        endpoints.push({
          path: p,
          introspection: true,
          typeCount: schema.types.length,
          queryType: schema.queryType?.name || null,
          mutationType: schema.mutationType?.name || null,
          sampleTypes: schema.types.filter(t => t.kind === 'OBJECT' && !t.name.startsWith('__')).slice(0, 15).map(t => t.name),
        });
      } else if (typeof res.data === 'object' && (res.data.errors || res.data.data !== undefined)) {
        // Responded like GraphQL but introspection is disabled — still worth noting.
        endpoints.push({ path: p, introspection: false });
      }
    } catch { /* not a GraphQL endpoint here */ }
  }

  const findings = endpoints
    .filter(e => e.introspection)
    .map(e => ({ severity: 'medium', message: `GraphQL introspection exposed at ${e.path} (${e.typeCount} types)` }));

  return { target: host, pathsTried: paths.length, endpoints, introspectionExposed: findings.length > 0, findings };
}
