import { resolveDNS, reverseDNS } from './src/dns.js';
import { passive } from './src/subdomains.js';

/** DNS reconnaissance — records, reverse/PTR sweeps, passive subdomains. */
export default {
  name: 'dns',
  version: '1.0.0',
  domain: 'dns',
  description: 'DNS reconnaissance — records, reverse/PTR sweeps, and passive subdomains.',
  permissions: { network: ['dns', 'https'], env: [], bins: [] },
  executors: [
    {
      uses: 'dns.resolve',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain', 'ip'],
      summary: 'Resolve DNS records (A/AAAA/CNAME/NS/MX/TXT/PTR/SOA).',
      run: resolveDNS,
      inputSchema: {
        target: { type: 'string', description: 'Domain to query (e.g. "example.com")' },
        types: { type: 'array', items: { type: 'string' }, description: 'Record types. Default: ["A","AAAA"]' },
      },
    },
    {
      uses: 'dns.reverse',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['ip', 'cidr', 'domain'],
      summary: 'Reverse DNS (PTR) lookup or CIDR sweep.',
      run: reverseDNS,
      inputSchema: {
        target: { type: 'string', description: 'IP, IPv4 CIDR, or hostname' },
        maxHosts: { type: 'number', description: 'Max addresses for a CIDR sweep. Default: 256' },
      },
    },
    {
      uses: 'subdomains.passive',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain'],
      summary: 'Passive subdomain enumeration via certificate transparency (crt.sh).',
      run: passive,
      inputSchema: {
        target: { type: 'string', description: 'Base domain (e.g. "example.com")' },
      },
    },
  ],
};
