import { intel } from './src/ip.js';

/** ASN / IP intelligence (Team Cymru; optional key-gated AbuseIPDB). */
export default {
  name: 'ip-intel',
  version: '1.0.0',
  domain: 'ip-intel',
  description: 'ASN / IP intelligence — ASN, BGP prefix, country, hosting/CDN class (key-gated abuse reputation).',
  permissions: { network: ['dns', 'https'], env: ['ABUSEIPDB_API_KEY'], bins: [] },
  executors: [
    {
      uses: 'ip.intel',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['ip', 'domain'],
      summary: 'ASN, BGP prefix, country, registry, and hosting/CDN classification.',
      run: intel,
      inputSchema: {
        target: { type: 'string', description: 'IP or hostname (hostname is A-resolved)' },
        ip: { type: 'string', description: 'Explicit IP to analyse instead of resolving target (optional)' },
      },
    },
  ],
};
