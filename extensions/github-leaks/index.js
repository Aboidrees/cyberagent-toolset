import { leaks } from './src/github.js';

/** GitHub leaks — public code search for the target domain (key-gated). */
export default {
  name: 'github-leaks',
  version: '1.0.0',
  domain: 'github-leaks',
  description: 'GitHub code search — public code referencing the target domain (requires GITHUB_TOKEN). Review matches manually.',
  permissions: { network: ['https'], env: ['GITHUB_TOKEN'], bins: [] },
  executors: [
    {
      uses: 'github.leaks',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain'],
      summary: 'Search public GitHub code for the target domain (no-op without a token).',
      run: leaks,
      inputSchema: {
        target: { type: 'string', description: 'Domain to search for' },
        query: { type: 'string', description: 'Custom code-search query (optional)' },
        token: { type: 'string', description: 'GitHub token (or set GITHUB_TOKEN env)' },
      },
    },
  ],
};
