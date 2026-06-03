import { hostLookup } from './src/shodan.js';
import { cveLookup } from './src/vuln.js';
import { epss } from './src/epss.js';
import { findings } from './report.js';

/** Threat intelligence — Shodan host data, NVD CVE lookup, and EPSS scoring. */
export default {
  name: 'threat-intel',
  version: '1.1.0',
  domain: 'threat-intel',
  description: 'Threat intelligence — Shodan host data (key-gated), NVD CVE lookup, and EPSS exploit-probability scoring (keyless).',
  permissions: { network: ['https'], env: ['SHODAN_API_KEY', 'NVD_API_KEY'], bins: [] },
  report: { findings },
  executors: [
    {
      uses: 'shodan.host',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['ip', 'domain'],
      summary: 'Shodan host data — open ports, services, banners, CVEs, tags (requires SHODAN_API_KEY).',
      run: hostLookup,
      inputSchema: {
        target: { type: 'string', description: 'IP or hostname (hostname is A-resolved)' },
        apiKey: { type: 'string', description: 'Shodan API key (or set SHODAN_API_KEY env)' },
      },
    },
    {
      uses: 'vuln.cve_lookup',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: [],
      summary: 'NVD CVE lookup by cpe / keyword / product+version (keyless; NVD_API_KEY raises rate limit).',
      run: cveLookup,
      inputSchema: {
        keyword: { type: 'string', description: 'Free-text search, e.g. "Apache 2.4.49"' },
        cpe: { type: 'string', description: 'Exact CPE 2.3 name (optional)' },
        product: { type: 'string', description: 'Product name (combined with version)' },
        version: { type: 'string', description: 'Product version' },
        minCvss: { type: 'number', description: 'Minimum CVSS base score. Default: 0' },
        severity: { type: 'string', description: 'Filter: LOW|MEDIUM|HIGH|CRITICAL' },
        maxResults: { type: 'number', description: 'Max CVEs to return. Default: 20' },
      },
    },
    {
      uses: 'vuln.epss',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: [],
      summary: 'EPSS exploit-probability scoring for one or more CVEs (FIRST.org, keyless).',
      run: epss,
      inputSchema: {
        cve: { type: 'string', description: 'CVE id or comma list, e.g. "CVE-2021-44228,CVE-2021-45046"' },
        minScore: { type: 'number', description: 'Only return CVEs with EPSS >= this (0..1). Default: 0' },
      },
    },
  ],
};
