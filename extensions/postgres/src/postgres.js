import net from 'net';
import { validateTarget } from '#sdk';

/**
 * PostgreSQL exposure probe. Sends the protocol SSLRequest (the cleanest read-only
 * way to fingerprint a Postgres listener) and reports whether the server offers
 * TLS. A Postgres port reachable from the internet — especially one that does not
 * offer SSL — is worth flagging. No authentication, no queries. Keyless.
 */
export async function postgresProbe(target, opts = {}) {
  const host = validateTarget(target);
  const port = opts.port || 5432;
  const timeoutMs = opts.timeoutMs || 8000;

  return new Promise((resolve) => {
    let settled = false;
    const fail = (error) => { if (settled) return; settled = true; sock.destroy(); resolve({ target: host, port, reachable: false, error, findings: [] }); };
    const sock = net.connect({ host, port });
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => {
      // SSLRequest: int32 length=8, int32 code=80877103.
      const buf = Buffer.alloc(8);
      buf.writeInt32BE(8, 0);
      buf.writeInt32BE(80877103, 4);
      sock.write(buf);
    });
    sock.on('data', (d) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      const reply = String.fromCharCode(d[0]); // 'S' = SSL, 'N' = no SSL, 'E' = error
      const isPostgres = reply === 'S' || reply === 'N';
      const findings = [];
      if (reply === 'N') findings.push({ severity: 'low', message: 'PostgreSQL does not offer SSL (connections would be cleartext)' });
      if (isPostgres) findings.push({ severity: 'info', message: `PostgreSQL reachable on ${host}:${port}` });
      resolve({ target: host, port, reachable: true, isPostgres, sslSupported: reply === 'S', reply, findings });
    });
    sock.on('timeout', () => fail('timeout'));
    sock.on('error', (e) => fail(e.code || e.message));
    sock.on('close', () => { if (!settled) fail('closed before response'); });
  });
}
