import { domainEmails } from './src/hunter.js';

/** Hunter.io email harvest — domain email footprint (key-gated). */
export default {
  name: 'hunter',
  version: '1.0.0',
  domain: 'hunter',
  description: 'Hunter.io email harvest — discover the email addresses, address pattern, and organization for a domain. Key-gated (HUNTER_API_KEY); no-op without a key.',
  permissions: { network: ['https'], env: ['HUNTER_API_KEY'], bins: [] },
  executors: [
    {
      uses: 'hunter.emails',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain'],
      summary: 'Hunter.io domain search — email addresses, pattern, organization (requires HUNTER_API_KEY).',
      run: domainEmails,
      inputSchema: {
        target: { type: 'string', description: 'Domain (e.g. "example.com")' },
        apiKey: { type: 'string', description: 'Hunter.io API key (or set HUNTER_API_KEY env)' },
        limit: { type: 'number', description: 'Max emails to return (1–100). Default: 25' },
      },
    },
  ],
};
