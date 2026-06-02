import { host } from './src/censys.js';

/** Censys — internet-wide host data (key-gated). */
export default {
  name: 'censys',
  version: '1.0.0',
  domain: 'censys',
  description: 'Censys host lookup — services, ports, software, ASN, location (requires CENSYS_API_ID + CENSYS_API_SECRET).',
  permissions: { network: ['https'], env: ['CENSYS_API_ID', 'CENSYS_API_SECRET'], bins: [] },
  executors: [
    {
      uses: 'censys.host',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['ip', 'domain'],
      summary: 'Censys host data — services, software, ASN, location (no-op without credentials).',
      run: host,
      inputSchema: {
        target: { type: 'string', description: 'IP or hostname (hostname is A-resolved)' },
        apiId: { type: 'string' }, apiSecret: { type: 'string' },
      },
    },
  ],
};
