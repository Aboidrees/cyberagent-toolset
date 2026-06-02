import net from 'net';
import { validateTarget } from '#sdk';
import { scanNmap } from './nmap.js';

/**
 * UDP port scan (nmap -sU). UDP scanning needs raw sockets → typically requires
 * root; without it nmap returns an error, captured in the output.
 */
export async function nmapUdp(target, opts = {}) {
  const flags = opts.flags || '-sU -Pn --top-ports 50';
  const r = await scanNmap(target, { flags, timeoutMs: opts.timeoutMs || 300000 });
  return { ...r, note: 'UDP scan usually requires root (sudo).' };
}

/**
 * OS fingerprint (nmap -O). Requires root; without it nmap reports it cannot
 * determine the OS.
 */
export async function nmapOs(target, opts = {}) {
  const flags = opts.flags || '-O -Pn';
  const r = await scanNmap(target, { flags, timeoutMs: opts.timeoutMs || 180000 });
  return { ...r, note: 'OS fingerprinting requires root (sudo).' };
}

// ── network.banner ───────────────────────────────────────────────────────────
const DEFAULT_PORTS = [21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 11211, 27017];

function grab(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    let data = '';
    const done = (val) => { if (!settled) { settled = true; try { sock.destroy(); } catch {} resolve(val); } };
    const sock = net.connect({ host, port }, () => {
      // Most text services (SSH/FTP/SMTP/POP3/IMAP/Redis) greet on connect.
    });
    sock.setTimeout(timeoutMs);
    sock.on('data', (chunk) => { data += chunk.toString('latin1'); if (data.length > 512) done({ port, open: true, banner: data.slice(0, 512).trim() }); });
    sock.on('timeout', () => done(data ? { port, open: true, banner: data.trim() } : { port, open: true, banner: null }));
    sock.on('error', () => done({ port, open: false }));
    sock.on('close', () => done(data ? { port, open: true, banner: data.trim() } : { port, open: false }));
  });
}

/**
 * TCP service banner grab — connects to a set of ports and captures the greeting
 * banner (SSH/FTP/SMTP/Redis/etc.). Active; authorized targets only.
 */
export async function banner(target, opts = {}) {
  const host = validateTarget(target);
  const ports = opts.ports || DEFAULT_PORTS;
  const timeoutMs = opts.timeoutMs || 4000;
  const concurrency = Math.min(opts.concurrency || 10, 32);

  const results = [];
  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = await Promise.all(ports.slice(i, i + concurrency).map(p => grab(host, p, timeoutMs)));
    results.push(...batch);
  }
  const open = results.filter(r => r.open);
  return { target: host, portsTried: ports.length, openCount: open.length, services: open };
}
