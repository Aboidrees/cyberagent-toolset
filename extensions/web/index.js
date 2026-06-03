import {
  getHeaders, getPath, securityScore, wafDetect, fingerprint,
  corsCheck, methods, fuzzPaths, gitLeak,
} from './src/http.js';
import { wayback, secrets, openRedirect, subdomainTakeover, robots, cookies } from './src/advanced.js';
import { findings } from './report.js';

const url = { type: 'string', description: 'URL path. Default: "/"' };
const scheme = { type: 'string', description: '"http" or "https". Default: "https"' };

/** Web surface — HTTP scanning and read-only exposure checks. */
export default {
  name: 'web',
  version: '1.1.0',
  domain: 'web',
  description: 'Web surface — headers/content, header grade, WAF/CDN, tech fingerprint, CORS, methods, cookies, robots, path fuzzing, secrets, open-redirect, subdomain-takeover, .git exposure, and Wayback URLs.',
  permissions: { network: ['http', 'https'], env: [], bins: [] },
  report: { findings },
  executors: [
    {
      uses: 'http.headers', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'url', 'ip'],
      summary: 'HTTP response headers — server banner, security headers, cookies.',
      run: getHeaders, inputSchema: { target: { type: 'string' }, path: url, scheme },
    },
    {
      uses: 'http.get', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'url', 'ip'],
      summary: 'Full HTTP GET — status, headers, and a body snippet.',
      run: getPath, inputSchema: { target: { type: 'string' }, path: url, scheme },
    },
    {
      uses: 'http.security_score', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'url', 'ip'],
      summary: 'A–F security-header grade with per-header remediation advice.',
      run: securityScore, inputSchema: { target: { type: 'string' }, path: url, scheme },
    },
    {
      uses: 'http.waf_detect', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'url', 'ip'],
      summary: 'WAF / CDN fingerprint from headers, cookies, and banners.',
      run: wafDetect, inputSchema: { target: { type: 'string' }, path: url, scheme },
    },
    {
      uses: 'http.fingerprint', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'url', 'ip'],
      summary: 'Technology stack fingerprint from headers and HTML body.',
      run: fingerprint, inputSchema: { target: { type: 'string' }, path: url, scheme, deep: { type: 'boolean', description: 'Inspect body. Default: true' } },
    },
    {
      uses: 'http.cors_check', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'url', 'ip'],
      summary: 'CORS misconfiguration probe (origin reflection, wildcard+credentials).',
      run: corsCheck, inputSchema: { target: { type: 'string' }, path: url, scheme, origin: { type: 'string', description: 'Test Origin header' } },
    },
    {
      uses: 'http.methods', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'url', 'ip'],
      summary: 'HTTP methods audit — OPTIONS + risky-method probe (PUT/DELETE/TRACE/PATCH).',
      run: methods, inputSchema: { target: { type: 'string' }, path: url, scheme },
    },
    {
      uses: 'http.fuzz_paths', phase: 'gaining-access', posture: 'active', targetTypes: ['domain', 'url', 'ip'],
      summary: 'Active path enumeration (built-in wordlists). Authorized targets only.',
      run: fuzzPaths, inputSchema: { target: { type: 'string' }, wordlist: { type: 'string', description: 'common|api|admin|php|asp' }, scheme, threads: { type: 'number' } },
    },
    {
      uses: 'http.git_leak', phase: 'gaining-access', posture: 'active', targetTypes: ['domain', 'url', 'ip'],
      summary: 'Exposed .git directory detector (flags critical on exposure).',
      run: gitLeak, inputSchema: { target: { type: 'string' }, scheme },
    },
    {
      uses: 'http.cookies', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'url', 'ip'],
      summary: 'Audit Set-Cookie security flags (Secure / HttpOnly / SameSite).',
      run: cookies, inputSchema: { target: { type: 'string' }, path: url, scheme },
    },
    {
      uses: 'http.robots', phase: 'reconnaissance', posture: 'active', targetTypes: ['domain', 'url'],
      summary: 'Parse robots.txt + sitemap.xml to surface revealed endpoints.',
      run: robots, inputSchema: { target: { type: 'string' }, scheme },
    },
    {
      uses: 'http.secrets', phase: 'gaining-access', posture: 'active', targetTypes: ['domain', 'url'],
      summary: 'Scan a page body for exposed secrets (API keys, tokens, private keys).',
      run: secrets, inputSchema: { target: { type: 'string' }, path: url, scheme },
    },
    {
      uses: 'http.open_redirect', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'url'],
      summary: 'Probe common open-redirect parameters.',
      run: openRedirect, inputSchema: { target: { type: 'string' }, path: url, scheme },
    },
    {
      uses: 'http.subdomain_takeover', phase: 'scanning', posture: 'active', targetTypes: ['domain'],
      summary: 'Detect dangling-CNAME subdomain takeover via service fingerprints.',
      run: subdomainTakeover, inputSchema: { target: { type: 'string' }, scheme },
    },
    {
      uses: 'web.wayback', phase: 'reconnaissance', posture: 'passive', targetTypes: ['domain'],
      summary: 'Archived URLs from the Wayback Machine (web.archive.org). Passive.',
      run: wayback, inputSchema: { target: { type: 'string' }, limit: { type: 'number', description: 'Max URLs. Default: 200' } },
    },
  ],
};
