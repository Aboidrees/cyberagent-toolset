import { virustotalLookup } from './src/virustotal.js';

/** VirusTotal — multi-vendor reputation for an IP or domain (key-gated). */
export default {
  name: 'virustotal',
  version: '1.0.0',
  domain: 'virustotal',
  description: 'VirusTotal reputation — how many vendors flag an IP/domain malicious + community score. Key-gated (VIRUSTOTAL_API_KEY).',
  permissions: { network: ['https'], env: ['VIRUSTOTAL_API_KEY'], bins: [] },
  executors: [
    {
      uses: 'virustotal.lookup', phase: 'reconnaissance', posture: 'passive', targetTypes: ['ip', 'domain'],
      summary: 'VirusTotal IP/domain reputation (malicious-vendor count + reputation). Requires VIRUSTOTAL_API_KEY.',
      run: virustotalLookup,
      inputSchema: { target: { type: 'string', description: 'IP or domain' }, apiKey: { type: 'string', description: 'VT key (or VIRUSTOTAL_API_KEY)' } },
    },
  ],
};
