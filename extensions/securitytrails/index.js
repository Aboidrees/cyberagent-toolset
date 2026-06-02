import { subdomains, dnsHistory } from './src/securitytrails.js';

/** SecurityTrails — passive DNS history (key-gated). */
export default {
  name: 'securitytrails',
  version: '1.0.0',
  domain: 'securitytrails',
  description: 'SecurityTrails passive DNS — historical subdomains and A-record timelines (requires SECURITYTRAILS_API_KEY).',
  permissions: { network: ['https'], env: ['SECURITYTRAILS_API_KEY'], bins: [] },
  executors: [
    {
      uses: 'securitytrails.subdomains',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain'],
      summary: 'Historical subdomains from SecurityTrails (no-op without a key).',
      run: subdomains,
      inputSchema: { target: { type: 'string', description: 'Domain' }, apiKey: { type: 'string' } },
    },
    {
      uses: 'securitytrails.dns_history',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain'],
      summary: 'Historical A-record timeline from SecurityTrails (no-op without a key).',
      run: dnsHistory,
      inputSchema: { target: { type: 'string', description: 'Domain' }, apiKey: { type: 'string' } },
    },
  ],
};
