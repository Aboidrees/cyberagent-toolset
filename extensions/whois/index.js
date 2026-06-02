import { lookupWhois } from './src/whois.js';

/** WHOIS registration lookup. */
export default {
  name: 'whois',
  version: '1.0.0',
  domain: 'whois',
  description: 'WHOIS registration data — registrar, dates, name servers, registrant, abuse contact.',
  permissions: { network: ['whois'], env: [], bins: [] },
  executors: [
    {
      uses: 'whois.lookup',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain', 'ip'],
      summary: 'WHOIS lookup for a domain or IP.',
      run: lookupWhois,
      inputSchema: {
        target: { type: 'string', description: 'Domain or IP address' },
      },
    },
  ],
};
