import { binaryedgeHost } from './src/binaryedge.js';

/** BinaryEdge — internet-scan host data (ports/services) (key-gated). */
export default {
  name: 'binaryedge',
  version: '1.0.0',
  domain: 'binaryedge',
  description: 'BinaryEdge — internet-wide scan data for a host (open ports + observed services). Key-gated (BINARYEDGE_API_KEY).',
  permissions: { network: ['https', 'dns'], env: ['BINARYEDGE_API_KEY'], bins: [] },
  executors: [
    {
      uses: 'binaryedge.host', phase: 'reconnaissance', posture: 'passive', targetTypes: ['ip', 'domain'],
      summary: 'BinaryEdge host data — open ports + services from internet scans. Requires BINARYEDGE_API_KEY.',
      run: binaryedgeHost,
      inputSchema: { target: { type: 'string', description: 'IP or hostname (A-resolved)' }, apiKey: { type: 'string', description: 'BinaryEdge key (or BINARYEDGE_API_KEY)' } },
    },
  ],
};
