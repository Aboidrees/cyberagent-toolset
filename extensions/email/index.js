import { security } from './src/email.js';
import { smtpProbe } from './src/smtp.js';

/** Email posture — DNS authentication (SPF/DMARC/DKIM/MTA-STS/BIMI) + live SMTP probe. */
export default {
  name: 'email',
  version: '1.1.0',
  domain: 'email',
  description: 'Email posture — SPF, DMARC, DKIM, MTA-STS, BIMI (passive DNS), plus a live SMTP STARTTLS/AUTH probe.',
  permissions: { network: ['dns', 'https', 'tcp'], env: [], bins: [] },
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
    {
      uses: 'smtp.probe',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'SMTP EHLO probe — STARTTLS support, AUTH mechanisms, cleartext-auth + optional open-relay test.',
      run: smtpProbe,
      inputSchema: {
        target: { type: 'string', description: 'Domain (MX is resolved) or mail-server host' },
        port: { type: 'number', description: 'SMTP port. Default: 25' },
        mx: { type: 'string', description: 'Override the MX host to probe (optional)' },
        relayTest: { type: 'boolean', description: 'Run a read-only open-relay heuristic (aborts before DATA). Default: false' },
        timeoutMs: { type: 'number', description: 'Per-step timeout ms. Default: 10000' },
      },
    },
  ],
};
