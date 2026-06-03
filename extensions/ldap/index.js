import { ldapProbe } from './src/ldap.js';

/** LDAP anonymous-bind probe (read-only, no search). */
export default {
  name: 'ldap',
  version: '1.0.0',
  domain: 'ldap',
  description: 'LDAP anonymous-bind probe — checks whether the directory accepts an unauthenticated bind (enumeration exposure). Read-only.',
  permissions: { network: ['tcp'], env: [], bins: [] },
  executors: [
    {
      uses: 'ldap.probe', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'ip'],
      summary: 'LDAP anonymous simple-bind check — flags directories enumerable without creds.',
      run: ldapProbe,
      inputSchema: { target: { type: 'string', description: 'Hostname or IP' }, port: { type: 'number', description: 'Default: 389' }, timeoutMs: { type: 'number' } },
    },
  ],
};
