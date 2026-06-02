import { security } from './src/email.js';

/** Email authentication posture (SPF/DMARC/DKIM/MTA-STS/BIMI). */
export default {
  name: 'email',
  version: '1.0.0',
  domain: 'email',
  description: 'Email authentication posture — SPF, DMARC, DKIM, MTA-STS, and BIMI (passive DNS).',
  permissions: { network: ['dns', 'https'], env: [], bins: [] },
  executors: [
    {
      uses: 'email.security',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain'],
      summary: 'SPF, DMARC, DKIM, MTA-STS, and BIMI posture with severity findings.',
      run: security,
      inputSchema: {
        target: { type: 'string', description: 'Domain (e.g. "example.com")' },
        selectors: { type: 'array', items: { type: 'string' }, description: 'DKIM selectors to probe (optional)' },
      },
    },
  ],
};
