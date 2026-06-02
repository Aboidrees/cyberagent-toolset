import { ping } from './src/ping.js';
import { traceroute } from './src/traceroute.js';
import { scanNmap } from './src/nmap.js';

/** Network scanning — liveness (ping/traceroute) and port/service scanning (nmap). */
export default {
  name: 'network',
  version: '1.0.0',
  domain: 'network',
  description: 'Network scanning — ICMP ping, traceroute, and nmap port/service scanning.',
  permissions: { network: ['icmp', 'tcp'], env: [], bins: ['ping', 'traceroute', 'nmap'] },
  executors: [
    {
      uses: 'network.ping',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'ICMP ping — reachability, packet loss, latency.',
      run: ping,
      inputSchema: {
        target: { type: 'string', description: 'Hostname or IP' },
        count: { type: 'number', description: 'Packets. Default: 4' },
      },
    },
    {
      uses: 'network.traceroute',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'Traceroute — hop-by-hop network path.',
      run: traceroute,
      inputSchema: {
        target: { type: 'string', description: 'Hostname or IP' },
        maxHops: { type: 'number', description: 'Max hops. Default: 30' },
      },
    },
    {
      uses: 'nmap.scan',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip', 'cidr'],
      summary: 'nmap port scan (non-privileged TCP connect by default). Authorized targets only.',
      run: scanNmap,
      inputSchema: {
        target: { type: 'string', description: 'Hostname, IP, or CIDR' },
        flags: { type: 'string', description: 'nmap flags. Default: "-sT -Pn --top-ports 1000"' },
        timeoutMs: { type: 'number', description: 'Timeout ms. Default: 300000' },
      },
    },
  ],
};
