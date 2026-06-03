import { postgresProbe } from './src/postgres.js';

/** PostgreSQL exposure probe — SSLRequest fingerprint (read-only, no auth). */
export default {
  name: 'postgres',
  version: '1.0.0',
  domain: 'postgres',
  description: 'PostgreSQL exposure probe — fingerprints a listener via the protocol SSLRequest and reports TLS availability. No authentication.',
  permissions: { network: ['tcp'], env: [], bins: [] },
  executors: [
    {
      uses: 'postgres.probe', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'ip'],
      summary: 'PostgreSQL SSLRequest probe — detect a Postgres listener + TLS availability.',
      run: postgresProbe,
      inputSchema: { target: { type: 'string', description: 'Hostname or IP' }, port: { type: 'number', description: 'Default: 5432' }, timeoutMs: { type: 'number' } },
    },
  ],
};
