import { inspectTLS, deepTLS } from './src/tls.js';
import { ctlog } from './src/ctlog.js';

/** TLS inspection — certificate metadata, deep analysis, and CT-log history. */
export default {
  name: 'tls',
  version: '1.1.0',
  domain: 'tls',
  description: 'TLS inspection — certificate metadata, deep analysis (protocols, weak ciphers, chain, OCSP, HSTS), and Certificate Transparency history.',
  permissions: { network: ['tls', 'https'], env: [], bins: [] },
  executors: [
    {
      uses: 'tls.inspect',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'TLS certificate + cipher inspection (subject, SANs, issuer, validity).',
      run: inspectTLS,
      inputSchema: {
        target: { type: 'string', description: 'Hostname' },
        port: { type: 'number', description: 'TLS port. Default: 443' },
      },
    },
    {
      uses: 'tls.deep',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'Deep TLS — protocol matrix, weak-cipher probes, chain validation, OCSP, HSTS.',
      run: deepTLS,
      inputSchema: {
        target: { type: 'string', description: 'Hostname' },
        port: { type: 'number', description: 'TLS port. Default: 443' },
        timeoutMs: { type: 'number', description: 'Per-probe timeout ms. Default: 10000' },
      },
    },
    {
      uses: 'cert.ctlog',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain'],
      summary: 'Certificate Transparency history via crt.sh — issuers, timeline, observed names.',
      run: ctlog,
      inputSchema: {
        target: { type: 'string', description: 'Domain' },
        limit: { type: 'number', description: 'Max recent certs to return. Default: 50' },
        includeSubdomains: { type: 'boolean', description: 'Also return unique SAN/CN names. Default: false' },
        timeoutMs: { type: 'number', description: 'Request timeout ms. Default: 30000' },
      },
    },
  ],
};
