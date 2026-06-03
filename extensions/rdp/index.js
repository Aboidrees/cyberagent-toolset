import { rdpProbe } from './src/rdp.js';

/** RDP security probe — negotiated protocol / NLA check (read-only, no auth). */
export default {
  name: 'rdp',
  version: '1.0.0',
  domain: 'rdp',
  description: 'RDP security probe — X.224 negotiation reporting the selected security protocol; flags Standard RDP Security (no TLS/NLA). No credentials.',
  permissions: { network: ['tcp'], env: [], bins: [] },
  executors: [
    {
      uses: 'rdp.probe', phase: 'scanning', posture: 'active', targetTypes: ['domain', 'ip'],
      summary: 'RDP negotiation probe — selected security protocol; flags missing NLA.',
      run: rdpProbe,
      inputSchema: { target: { type: 'string', description: 'Hostname or IP' }, port: { type: 'number', description: 'Default: 3389' }, timeoutMs: { type: 'number' } },
    },
  ],
};
