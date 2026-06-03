import net from 'net';
import { validateTarget } from '#sdk';

/**
 * RDP security probe. Sends an X.224 Connection Request with an RDP Negotiation
 * Request and reads which security protocol the server selects. The key finding
 * is **Standard RDP Security** (no TLS/NLA) — it leaves the session open to MITM
 * and predates Network Level Authentication. Read-only handshake, no credentials.
 */

const PROTOCOLS = { 0: 'Standard RDP Security', 1: 'TLS', 2: 'CredSSP (NLA)', 8: 'RDSTLS' };

// TPKT + X.224 CR + RDP Negotiation Request (requestedProtocols = TLS|CredSSP).
function buildConnectionRequest() {
  return Buffer.from([
    0x03, 0x00, 0x00, 0x13,             // TPKT: version 3, length 19
    0x0e,                               // X.224 LI = 14
    0xe0,                               // CR (connection request)
    0x00, 0x00,                         // dst ref
    0x00, 0x00,                         // src ref
    0x00,                               // class
    0x01, 0x00, 0x08, 0x00,             // RDP Neg Req: type=1, flags=0, length=8
    0x03, 0x00, 0x00, 0x00,             // requestedProtocols = TLS | CredSSP
  ]);
}

export async function rdpProbe(target, opts = {}) {
  const host = validateTarget(target);
  const port = opts.port || 3389;
  const timeoutMs = opts.timeoutMs || 8000;

  return new Promise((resolve) => {
    let settled = false;
    const fail = (error) => { if (settled) return; settled = true; sock.destroy(); resolve({ target: host, port, reachable: false, error, findings: [] }); };
    const sock = net.connect({ host, port });
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => sock.write(buildConnectionRequest()));
    sock.on('data', (buf) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      // TPKT(4) + X.224 CC(7) then RDP Neg Response: type@11, selectedProtocol@15 (LE).
      if (buf.length < 12) return resolve({ target: host, port, reachable: true, isRDP: true, note: 'short response', findings: [] });
      const type = buf[11];
      if (type === 0x03) {
        return resolve({ target: host, port, reachable: true, isRDP: true, negotiation: 'failure', findings: [] });
      }
      const proto = buf.length >= 19 ? buf.readUInt32LE(15) : 0;
      const findings = [];
      if (proto === 0) findings.push({ severity: 'medium', message: 'RDP allows Standard Security (no TLS/NLA) — exposed to MITM; enable Network Level Authentication' });
      resolve({
        target: host, port, reachable: true, isRDP: true,
        selectedProtocol: proto, security: PROTOCOLS[proto] || `0x${proto.toString(16)}`,
        nla: proto >= 2, findings,
      });
    });
    sock.on('timeout', () => fail('timeout'));
    sock.on('error', (e) => fail(e.code || e.message));
    sock.on('close', () => { if (!settled) fail('closed before negotiation response'); });
  });
}
