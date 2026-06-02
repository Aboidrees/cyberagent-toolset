import {
  getHeaders, getPath, securityScore, wafDetect, fingerprint,
  corsCheck, methods, fuzzPaths, gitLeak,
} from './src/http.js';
import { findings } from './report.js';

const url = { type: 'string', description: 'URL path. Default: "/"' };
const scheme = { type: 'string', description: '"http" or "https". Default: "https"' };

/** Web surface — HTTP scanning and read-only exposure checks. */
export default {
  name: 'web',
  version: '1.0.0',
  domain: 'web',
  description: 'Web surface — HTTP headers/content, header grade, WAF/CDN, tech fingerprint, CORS, methods, path fuzzing, and .git exposure.',
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
  ],
};
