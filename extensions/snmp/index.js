import { snmpProbe } from './src/snmp.js';

/** SNMP exposure probe — default/guessable community-string check (read-only). */
export default {
  name: 'snmp',
  version: '1.0.0',
  domain: 'snmp',
  description: 'SNMP exposure probe — checks whether UDP/161 answers a read-only SNMPv2c GET (sysDescr) on default/guessable community strings.',
  permissions: { network: ['udp'], env: [], bins: [] },
  executors: [
    {
      uses: 'snmp.probe',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'SNMPv2c community-string probe (public/private/…) — flags exposed agents.',
      run: snmpProbe,
      inputSchema: {
        target: { type: 'string', description: 'Hostname or IP' },
        port: { type: 'number', description: 'SNMP UDP port. Default: 161' },
        communities: { type: 'array', items: { type: 'string' }, description: 'Community strings to try (default: public/private/community/manager)' },
        timeoutMs: { type: 'number', description: 'Per-community timeout ms. Default: 4000' },
      },
    },
  ],
};
