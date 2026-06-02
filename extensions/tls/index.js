import { inspectTLS, deepTLS } from './src/tls.js';

/** TLS inspection — certificate metadata and vulnerability-oriented deep analysis. */
export default {
  name: 'tls',
  version: '1.0.0',
  domain: 'tls',
  description: 'TLS inspection — certificate metadata and deep analysis (protocols, weak ciphers, chain, OCSP, HSTS).',
  permissions: { network: ['tls'], env: [], bins: [] },
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
  ],
};
