import { bucketFinder } from './src/cloud.js';
import { bucketObjects } from './src/objects.js';
import { findings } from './report.js';

/** Cloud exposure — public storage bucket discovery + object enumeration. */
export default {
  name: 'cloud',
  version: '1.1.0',
  domain: 'cloud',
  description: 'Cloud exposure — public AWS S3 / GCP / Azure bucket discovery and object/ACL enumeration (read-only).',
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
    {
      uses: 'cloud.bucket_objects',
      phase: 'gaining-access',
      posture: 'active',
      targetTypes: ['domain'],
      summary: 'List objects in a public-listable bucket; flags sensitive keys (backups, dumps, secrets).',
      run: bucketObjects,
      inputSchema: {
        target: { type: 'string', description: 'Base domain (informational) — or pass url/bucket below' },
        url: { type: 'string', description: 'Full bucket base URL (e.g. https://name.s3.amazonaws.com/)' },
        bucket: { type: 'string', description: 'Bucket name (with provider)' },
        provider: { type: 'string', description: 'aws-s3 | gcp-gcs | azure' },
        container: { type: 'string', description: 'Azure container name (default: $root)' },
        limit: { type: 'number', description: 'Max objects to return. Default: 200' },
        timeoutMs: { type: 'number', description: 'Request timeout ms. Default: 15000' },
      },
    },
  ],
};
