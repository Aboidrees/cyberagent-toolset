import { ping } from './src/ping.js';
import { traceroute } from './src/traceroute.js';
import { scanNmap } from './src/nmap.js';
import { nmapUdp, nmapOs, banner } from './src/advanced.js';

/** Network scanning — liveness (ping/traceroute) and port/service scanning (nmap). */
export default {
  name: 'network',
  version: '1.1.0',
  domain: 'network',
  description: 'Network scanning — ICMP ping, traceroute, nmap TCP/UDP/OS scans, and TCP service banner grabbing.',
  permissions: { network: ['icmp', 'tcp', 'udp'], env: [], bins: ['ping', 'traceroute', 'nmap'] },
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
    {
      uses: 'nmap.udp',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'nmap UDP scan (-sU). Usually requires root.',
      run: nmapUdp,
      inputSchema: { target: { type: 'string', description: 'Hostname or IP' }, flags: { type: 'string' } },
    },
    {
      uses: 'nmap.os',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'nmap OS fingerprint (-O). Requires root.',
      run: nmapOs,
      inputSchema: { target: { type: 'string', description: 'Hostname or IP' } },
    },
    {
      uses: 'network.banner',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'TCP service banner grab (SSH/FTP/SMTP/Redis/etc.). Authorized targets only.',
      run: banner,
      inputSchema: {
        target: { type: 'string', description: 'Hostname or IP' },
        ports: { type: 'array', items: { type: 'number' }, description: 'Ports to probe (optional)' },
      },
    },
  ],
};
