import { mysqlProbe } from './src/mysql.js';

/** MySQL/MariaDB exposure probe — handshake version banner (read-only, no auth). */
export default {
  name: 'mysql',
  version: '1.0.0',
  domain: 'mysql',
  description: 'MySQL/MariaDB exposure probe — reads the server handshake (protocol + version). No authentication.',
  permissions: { network: ['tcp'], env: [], bins: [] },
  executors: [
    {
      uses: 'mysql.probe', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'ip'],
      summary: 'MySQL/MariaDB handshake probe — server version from the greeting packet.',
      run: mysqlProbe,
      inputSchema: { target: { type: 'string', description: 'Hostname or IP' }, port: { type: 'number', description: 'Default: 3306' }, timeoutMs: { type: 'number' } },
    },
  ],
};
