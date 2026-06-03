import net from 'net';
import { validateTarget } from '#sdk';

/**
 * MySQL/MariaDB exposure probe. On connect, a MySQL server sends an initial
 * handshake packet announcing its protocol and version — read that and report it.
 * An internet-reachable MySQL is worth flagging; the version string also feeds
 * `vuln.cve_lookup`. Read-only: reads the greeting, sends nothing, never auths.
 */
export async function mysqlProbe(target, opts = {}) {
  const host = validateTarget(target);
  const port = opts.port || 3306;
  const timeoutMs = opts.timeoutMs || 8000;

  return new Promise((resolve) => {
    let settled = false;
    const fail = (error) => { if (settled) return; settled = true; sock.destroy(); resolve({ target: host, port, reachable: false, error, findings: [] }); };
    const sock = net.connect({ host, port });
    sock.setTimeout(timeoutMs);
    sock.on('data', (d) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      // Packet: [3-byte length][1-byte seq][payload]. payload[0] = protocol version.
      const payload = d.subarray(4);
      const protocol = payload[0];
      if (protocol === 0xff) {
        // ERR packet — often "Host is not allowed" / "too many connections".
        const msg = payload.subarray(3).toString('latin1').replace(/[^\x20-\x7e]/g, '').trim();
        return resolve({ target: host, port, reachable: true, isMySQL: true, error: `server rejected: ${msg}`, findings: [] });
      }
      let end = 1;
      while (end < payload.length && payload[end] !== 0) end++;
      const serverVersion = payload.toString('latin1', 1, end);
      const findings = [{ severity: 'info', message: `MySQL/MariaDB ${serverVersion} reachable on ${host}:${port}` }];
      resolve({ target: host, port, reachable: true, isMySQL: protocol === 10, protocol, serverVersion, findings });
    });
    sock.on('timeout', () => fail('timeout'));
    sock.on('error', (e) => fail(e.code || e.message));
    sock.on('close', () => { if (!settled) fail('closed before handshake'); });
  });
}
