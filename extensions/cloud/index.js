import { bucketFinder } from './src/cloud.js';
import { findings } from './report.js';

/** Cloud exposure — public storage bucket discovery. */
export default {
  name: 'cloud',
  version: '1.0.0',
  domain: 'cloud',
  description: 'Cloud exposure — public AWS S3 / GCP / Azure storage bucket discovery (read-only).',
  permissions: { network: ['https'], env: [], bins: [] },
  report: { findings },
  executors: [
    {
      uses: 'cloud.bucket_finder',
      phase: 'gaining-access',
      posture: 'active',
      targetTypes: ['domain'],
      summary: 'Probe AWS S3 / GCP / Azure for public buckets derived from the domain.',
      run: bucketFinder,
      inputSchema: {
        target: { type: 'string', description: 'Base domain (e.g. "example.com")' },
        extraNames: { type: 'array', items: { type: 'string' }, description: 'Extra candidate bucket names (optional)' },
      },
    },
  ],
};
