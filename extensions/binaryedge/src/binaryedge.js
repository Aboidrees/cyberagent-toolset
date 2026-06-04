import dns from 'dns/promises';
import axios from 'axios';
import { validateTarget } from '#sdk';

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
async function toIp(target) {
  if (IPV4.test(target)) return target;
  const a = await dns.resolve4(target);
  if (!a.length) throw new Error(`could not resolve ${target}`);
  return a[0];
}

/**
 * BinaryEdge — internet-wide scan data for a host: open ports and the services
 * BinaryEdge observed on them (like Shodan/Censys, a different data source).
 * Key-gated (free tier); no-op without it.
 */
export async function binaryedgeHost(target, opts = {}, ctx = {}) {
  const clean = validateTarget(target);
  const apiKey = opts.apiKey || (ctx.env ? ctx.env('BINARYEDGE_API_KEY') : process.env.BINARYEDGE_API_KEY);
  if (!apiKey) {
    return { target: clean, checked: false, note: 'Skipped — set BINARYEDGE_API_KEY (free tier: binaryedge.io) to enable.' };
  }
  let ip;
  try { ip = await toIp(clean); } catch (e) { return { target: clean, checked: false, note: e.message }; }

  const res = await axios.get(`https://api.binaryedge.io/v2/query/ip/${ip}`, {
    headers: { 'X-Key': apiKey, accept: 'application/json' },
    timeout: opts.timeoutMs || 15000, validateStatus: () => true, maxContentLength: 8_000_000,
  });
  if (res.status === 401 || res.status === 403) return { target: clean, ip, checked: false, note: `BinaryEdge auth error (${res.status}).` };
  if (res.status === 404) return { target: clean, ip, checked: true, found: false, note: 'No BinaryEdge data for this IP.' };
  if (res.status !== 200 || !res.data) return { target: clean, ip, checked: false, note: `BinaryEdge HTTP ${res.status}` };

  const events = res.data.events || [];
  const ports = [...new Set(events.map(e => e.port).filter(Boolean))].sort((a, b) => a - b);
  const services = [...new Set(events.flatMap(e => (e.results || []).map(r => r.result?.data?.service?.name).filter(Boolean)))];
  const findings = ports.length ? [{ severity: 'info', message: `BinaryEdge: ${ports.length} open port(s) on ${ip} — ${ports.slice(0, 20).join(', ')}` }] : [];

  return { target: clean, ip, checked: true, found: events.length > 0, ports, services, total: res.data.total ?? events.length, findings };
}
