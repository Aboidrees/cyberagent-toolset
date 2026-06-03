import { rdapLookup } from './src/rdap.js';

/** RDAP — structured, JSON-over-HTTPS registration data (the modern WHOIS). */
export default {
  name: 'rdap',
  version: '1.0.0',
  domain: 'rdap',
  description: 'RDAP (RFC 9083) registration data — registrar, status, key dates, abuse contact, nameservers, DNSSEC; works for domains and IPs. Keyless.',
  permissions: { network: ['https'], env: [], bins: [] },
  executors: [
    {
      uses: 'rdap.lookup',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain', 'ip'],
      summary: 'RDAP registration lookup for a domain or IP (structured WHOIS over HTTPS).',
      run: rdapLookup,
      inputSchema: {
        target: { type: 'string', description: 'Domain or IP address' },
        timeoutMs: { type: 'number', description: 'Request timeout ms. Default: 15000' },
      },
    },
  ],
};
