import net from 'net';
import { validateTarget } from '#sdk';
import { scanNmap } from './nmap.js';

/**
 * UDP port scan (nmap -sU). UDP scanning needs raw sockets → typically requires
 * root; without it nmap returns an error, captured in the output.
 */
async function rootScan(target, flags, timeoutMs, label) {
  try {
    const r = await scanNmap(target, { flags, timeoutMs });
    return { ...r, note: `${label} requires root for full results (sudo).` };
  } catch (e) {
    // No-op gracefully when root is the only blocker (common, non-fatal).
    if (/root|privile/i.test(e.message)) {
      return { target, checked: false, note: `Skipped — ${label} requires root (sudo).` };
    }
    throw e;
  }
}

export async function nmapUdp(target, opts = {}) {
  return rootScan(target, opts.flags || '-sU -Pn --top-ports 50', opts.timeoutMs || 300000, 'UDP scan');
}

/**
 * OS fingerprint (nmap -O). Requires root; no-ops with a note otherwise.
 */
export async function nmapOs(target, opts = {}) {
  return rootScan(target, opts.flags || '-O -Pn', opts.timeoutMs || 180000, 'OS fingerprint');
}

// ── network.banner ───────────────────────────────────────────────────────────
const DEFAULT_PORTS = [21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 11211, 27017];

function grab(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    let data = '';
    let connected = false;
    let timer;
    const done = (val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch {}
      resolve(val);
    };
    const sock = net.connect({ host, port }, () => { connected = true; });
    // Hard timer — covers a dropped SYN (where the socket would otherwise wait for
    // the OS connect timeout, tens of seconds). On timeout: open+banner if we got
    // data, "filtered" if connected but silent, else closed.
    timer = setTimeout(() => done(
      data ? { port, open: true, banner: data.trim() }
           : connected ? { port, open: true, banner: null }
           : { port, open: false, filtered: true }), timeoutMs);
    sock.on('data', (chunk) => {
      data += chunk.toString('latin1');
      if (data.length > 512) done({ port, open: true, banner: data.slice(0, 512).trim() });
    });
    sock.on('error', () => done({ port, open: false }));
    sock.on('close', () => done(data ? { port, open: true, banner: data.trim() } : { port, open: connected }));
  });
}

/**
 * TCP service banner grab — connects to a set of ports and captures the greeting
 * banner (SSH/FTP/SMTP/Redis/etc.). Active; authorized targets only.
 */
export async function banner(target, opts = {}) {
  const host = validateTarget(target);
  const ports = opts.ports || DEFAULT_PORTS;
  // Per-port timeout, independent of the runner's step budget (timeoutMs).
  const reqTimeoutMs = opts.requestTimeoutMs || 4000;
  const concurrency = Math.min(opts.concurrency || 10, 32);

  const results = [];
  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = await Promise.all(ports.slice(i, i + concurrency).map(p => grab(host, p, reqTimeoutMs)));
    results.push(...batch);
  }
  const open = results.filter(r => r.open);
  return { target: host, portsTried: ports.length, openCount: open.length, services: open };
}
