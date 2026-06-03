import { resolveDNS, reverseDNS } from './src/dns.js';
import { passive } from './src/subdomains.js';
import { dnssec, caa, bruteforce, txtFingerprint } from './src/advanced.js';

/** DNS reconnaissance — records, reverse/PTR sweeps, passive subdomains. */
export default {
  name: 'dns',
  version: '1.1.0',
  domain: 'dns',
  description: 'DNS reconnaissance — records, reverse/PTR sweeps, passive subdomains, DNSSEC, CAA, and subdomain brute-force.',
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
    {
      uses: 'dns.dnssec',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain'],
      summary: 'DNSSEC posture (DNSKEY/DS + AD flag) via DNS-over-HTTPS.',
      run: dnssec,
      inputSchema: { target: { type: 'string', description: 'Domain' } },
    },
    {
      uses: 'dns.caa',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain'],
      summary: 'CAA records — which CAs may issue certificates for the domain.',
      run: caa,
      inputSchema: { target: { type: 'string', description: 'Domain' } },
    },
    {
      uses: 'subdomains.bruteforce',
      phase: 'reconnaissance',
      posture: 'active',
      targetTypes: ['domain'],
      summary: 'Active subdomain brute-force against a built-in wordlist.',
      run: bruteforce,
      inputSchema: {
        target: { type: 'string', description: 'Base domain' },
        wordlist: { type: 'array', items: { type: 'string' }, description: 'Custom subdomain list (optional)' },
        concurrency: { type: 'number', description: 'Parallel lookups. Default: 20' },
      },
    },
    {
      uses: 'dns.txt_fingerprint',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain'],
      summary: 'Fingerprint the SaaS / vendor footprint from TXT domain-verification tokens.',
      run: txtFingerprint,
      inputSchema: { target: { type: 'string', description: 'Domain' } },
    },
  ],
};
