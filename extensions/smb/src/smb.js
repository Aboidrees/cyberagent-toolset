import net from 'net';
import { validateTarget } from '#sdk';

/**
 * SMB negotiation probe. Sends an SMB2 NEGOTIATE over TCP/445 and reports the
 * negotiated dialect and signing posture. SMB signing **not required** is the
 * key finding — it leaves the host open to NTLM relay. Read-only: a single
 * NEGOTIATE exchange, no session setup, no authentication. Keyless.
 */

const DIALECTS = { 0x0202: 'SMB 2.0.2', 0x0210: 'SMB 2.1', 0x0300: 'SMB 3.0', 0x0302: 'SMB 3.0.2', 0x0311: 'SMB 3.1.1', 0x02ff: 'SMB 2.x wildcard' };
const OFFERED = [0x0202, 0x0210, 0x0300, 0x0302];

function buildNegotiate() {
  const header = Buffer.alloc(64);
  header.write('\xfeSMB', 0, 'latin1');        // ProtocolId 0xFE 'SMB'
  header.writeUInt16LE(64, 4);                 // StructureSize
  header.writeUInt16LE(0, 6);                  // CreditCharge
  header.writeUInt32LE(0, 8);                  // Status
  header.writeUInt16LE(0x0000, 12);            // Command = NEGOTIATE
  header.writeUInt16LE(1, 14);                 // CreditRequest
  // remaining fields stay zero

  const body = Buffer.alloc(36 + OFFERED.length * 2);
  body.writeUInt16LE(36, 0);                   // StructureSize
  body.writeUInt16LE(OFFERED.length, 2);       // DialectCount
  body.writeUInt16LE(0x0001, 4);               // SecurityMode = SIGNING_ENABLED
  body.writeUInt16LE(0, 6);                    // Reserved
  body.writeUInt32LE(0, 8);                    // Capabilities
  // ClientGuid (16B) + ClientStartTime (8B) stay zero
  OFFERED.forEach((d, i) => body.writeUInt16LE(d, 36 + i * 2));

  const smb = Buffer.concat([header, body]);
  // NetBIOS session service framing: 0x00 + 3-byte big-endian length.
  const nb = Buffer.alloc(4);
  nb.writeUInt8(0, 0);
  nb.writeUIntBE(smb.length, 1, 3);
  return Buffer.concat([nb, smb]);
}

function parseNegotiateResponse(buf) {
  // Skip 4-byte NetBIOS header; SMB2 header is 64 bytes.
  if (buf.length < 4 + 64 + 8) return null;
  const smb = buf.subarray(4);
  if (!(smb[0] === 0xfe && smb[1] === 0x53 && smb[2] === 0x4d && smb[3] === 0x42)) return null;
  const status = smb.readUInt32LE(8);
  const body = smb.subarray(64);
  if (body.length < 8) return null;
  const securityMode = body.readUInt16LE(2);
  const dialectRevision = body.readUInt16LE(4);
  return {
    status,
    dialectRevision,
    dialect: DIALECTS[dialectRevision] || `0x${dialectRevision.toString(16)}`,
    signingEnabled: Boolean(securityMode & 0x01),
    signingRequired: Boolean(securityMode & 0x02),
  };
}

export async function smbProbe(target, opts = {}) {
  const host = validateTarget(target);
  const port = opts.port || 445;
  const timeoutMs = opts.timeoutMs || 8000;

  return new Promise((resolve) => {
    const chunks = [];
    let settled = false;
    const fail = (err) => { if (settled) return; settled = true; socket.destroy(); resolve({ target: host, port, reachable: false, error: err, findings: [] }); };
    const socket = net.connect({ host, port });
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => socket.write(buildNegotiate()));
    socket.on('data', (d) => {
      chunks.push(d);
      const parsed = parseNegotiateResponse(Buffer.concat(chunks));
      if (!parsed) return; // need more bytes
      settled = true;
      socket.destroy();
      const findings = [];
      if (parsed.status === 0) {
        if (!parsed.signingRequired) {
          findings.push({ severity: 'medium', message: `SMB signing not required (${parsed.dialect}) — exposed to NTLM relay` });
        }
        if (parsed.dialectRevision === 0x0202) {
          findings.push({ severity: 'low', message: 'Only legacy SMB 2.0.2 negotiated' });
        }
      }
      resolve({ target: host, port, reachable: true, ...parsed, findings });
    });
    socket.on('timeout', () => fail('timeout'));
    socket.on('error', (e) => fail(e.code || e.message));
    socket.on('close', () => { if (!settled) fail('closed before SMB negotiate response'); });
  });
}
