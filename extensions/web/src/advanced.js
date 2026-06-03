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

// ── web.security_txt ─────────────────────────────────────────────────────────
/**
 * Fetch and parse a site's security.txt (RFC 9116). Checks the canonical
 * `/.well-known/security.txt` first, then the legacy `/security.txt`. Surfaces
 * the disclosure contact/policy and flags an expired policy.
 */
export async function securityTxt(target, opts = {}) {
  const host = validateTarget(target);
  const scheme = opts.scheme === 'http' ? 'http' : 'https';
  const candidates = ['/.well-known/security.txt', '/security.txt'];

  for (const path of candidates) {
    const url = buildUrl(scheme, host, path);
    let res;
    try {
      res = await axios.get(url, {
        timeout: opts.timeoutMs || 10000,
        validateStatus: () => true,
        maxRedirects: 3,
        maxContentLength: 200_000,
        responseType: 'text',
      });
    } catch { continue; }

    const body = typeof res.data === 'string' ? res.data : '';
    const ct = String(res.headers?.['content-type'] || '');
    // A real security.txt is text/plain and contains at least a Contact field.
    if (res.status !== 200 || !/contact:/i.test(body)) continue;

    const fields = {};
    for (const line of body.split(/\r?\n/)) {
      const m = /^([A-Za-z-]+):\s*(.+)$/.exec(line.trim());
      if (!m || line.trim().startsWith('#')) continue;
      const key = m[1].toLowerCase();
      (fields[key] ||= []).push(m[2].trim());
    }

    const findings = [];
    const expires = fields.expires?.[0];
    if (expires) {
      const exp = Date.parse(expires);
      if (!Number.isNaN(exp) && exp < Date.parse(res.headers?.date || '') ) {
        findings.push({ severity: 'low', message: `security.txt expired (${expires})` });
      }
    }
    return {
      target: host, found: true, url, contentType: ct,
      contact: fields.contact || [],
      policy: fields.policy || [],
      expires: expires || null,
      encryption: fields.encryption || [],
      fields, findings,
    };
  }

  return { target: host, found: false, url: buildUrl(scheme, host, candidates[0]), findings: [] };
}

// ── web.well_known ───────────────────────────────────────────────────────────
const WELL_KNOWN_PATHS = [
  '/.well-known/security.txt',
  '/.well-known/mta-sts.txt',
  '/.well-known/change-password',
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
  '/.well-known/assetlinks.json',
  '/.well-known/apple-app-site-association',
  '/.well-known/host-meta',
  '/.well-known/nodeinfo',
  '/.well-known/gpc.json',
  '/.well-known/dnt-policy.txt',
];
/**
 * Enumerate well-known URIs (RFC 8615). Surfaces policy/config endpoints a site
 * exposes — notably OAuth/OpenID discovery (auth surface) and MTA-STS/security
 * policies. Active: one HEAD/GET per path, concurrency-bounded.
 */
export async function wellKnown(target, opts = {}) {
  const host = validateTarget(target);
  const scheme = opts.scheme === 'http' ? 'http' : 'https';
  const timeoutMs = opts.timeoutMs || 8000;

  const probe = async (path) => {
    const url = buildUrl(scheme, host, path);
    try {
      const res = await axios.get(url, {
        timeout: timeoutMs, validateStatus: () => true,
        maxRedirects: 2, maxContentLength: 300_000, responseType: 'text',
      });
      return {
        path, url, status: res.status,
        contentType: String(res.headers?.['content-type'] || '').split(';')[0] || null,
        bytes: typeof res.data === 'string' ? res.data.length : 0,
        present: res.status >= 200 && res.status < 300,
      };
    } catch {
      return { path, url, status: null, present: false };
    }
  };

  const results = [];
  for (const p of WELL_KNOWN_PATHS) results.push(await probe(p));
  const present = results.filter(r => r.present);

  const findings = [];
  for (const r of present) {
    if (r.path.includes('openid-configuration') || r.path.includes('oauth-authorization-server')) {
      findings.push({ severity: 'info', message: `Auth discovery endpoint exposed: ${r.path}` });
    }
  }

  return { target: host, probed: results.length, presentCount: present.length, endpoints: present, findings };
}

// ── http.favicon_hash ────────────────────────────────────────────────────────
/** MurmurHash3 x86_32 (seed 0), signed — the hash Shodan/Censys index favicons by. */
function murmur3_32(bytes, seed = 0) {
  let h = seed >>> 0;
  const len = bytes.length;
  const nblocks = len >> 2;
  let k;
  for (let i = 0; i < nblocks; i++) {
    const j = i * 4;
    k = (bytes[j] & 0xff) | ((bytes[j + 1] & 0xff) << 8) | ((bytes[j + 2] & 0xff) << 16) | ((bytes[j + 3] & 0xff) << 24);
    k = Math.imul(k, 0xcc9e2d51); k = (k << 15) | (k >>> 17); k = Math.imul(k, 0x1b873593);
    h ^= k; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  k = 0;
  const tail = nblocks * 4;
  switch (len & 3) {
    case 3: k ^= (bytes[tail + 2] & 0xff) << 16; // falls through
    case 2: k ^= (bytes[tail + 1] & 0xff) << 8;  // falls through
    case 1: k ^= (bytes[tail] & 0xff);
      k = Math.imul(k, 0xcc9e2d51); k = (k << 15) | (k >>> 17); k = Math.imul(k, 0x1b873593); h ^= k;
  }
  h ^= len;
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return h | 0;
}
/**
 * Compute the Shodan/Censys favicon hash for a target. Replicates Python
 * `mmh3.hash(base64.encodebytes(favicon))` so the result can be pivoted on
 * (`http.favicon.hash:<n>`) to find other hosts serving the same favicon —
 * a cheap way to map related infrastructure. Keyless.
 */
export async function faviconHash(target, opts = {}) {
  const host = validateTarget(target);
  const scheme = opts.scheme === 'http' ? 'http' : 'https';
  const url = buildUrl(scheme, host, opts.path || '/favicon.ico');

  let res;
  try {
    res = await axios.get(url, {
      timeout: opts.timeoutMs || 10000, validateStatus: () => true,
      maxRedirects: 5, responseType: 'arraybuffer', maxContentLength: 5_000_000,
    });
  } catch (e) {
    return { target: host, url, error: e.message, hash: null };
  }
  if (res.status !== 200 || !res.data || !res.data.byteLength) {
    return { target: host, url, status: res.status, found: false, hash: null };
  }

  const buf = Buffer.from(res.data);
  // Python base64.encodebytes: 76-char lines, each newline-terminated.
  const b64 = buf.toString('base64');
  let mime = '';
  for (let i = 0; i < b64.length; i += 76) mime += b64.slice(i, i + 76) + '\n';

  return {
    target: host, url, status: res.status, found: true,
    bytes: buf.length,
    contentType: String(res.headers?.['content-type'] || '').split(';')[0] || null,
    hash: murmur3_32(Buffer.from(mime, 'ascii'), 0),
    shodanQuery: `http.favicon.hash:${murmur3_32(Buffer.from(mime, 'ascii'), 0)}`,
  };
}
