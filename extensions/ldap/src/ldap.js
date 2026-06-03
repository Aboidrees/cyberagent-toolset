import net from 'net';
import { validateTarget } from '#sdk';

/**
 * LDAP anonymous-bind probe. Sends a BER-encoded anonymous simple bind and reads
 * the result code. A server that accepts an anonymous bind (resultCode 0) lets an
 * unauthenticated client enumerate the directory — a classic information-exposure
 * finding. Read-only: a single bind, no search, no writes. Keyless.
 */

// LDAP anonymous simple bind (version 3, empty DN, empty password).
const ANON_BIND = Buffer.from([
  0x30, 0x0c,             // SEQUENCE, len 12
  0x02, 0x01, 0x01,       // messageID = 1
  0x60, 0x07,             // [APPLICATION 0] bindRequest, len 7
  0x02, 0x01, 0x03,       // version = 3
  0x04, 0x00,             // name = "" (octet string)
  0x80, 0x00,             // [0] simple authentication = "" (context tag)
]);

const RESULT = { 0: 'success', 1: 'operationsError', 49: 'invalidCredentials', 50: 'insufficientAccessRights', 53: 'unwillingToPerform' };

export async function ldapProbe(target, opts = {}) {
  const host = validateTarget(target);
  const port = opts.port || 389;
  const timeoutMs = opts.timeoutMs || 8000;

  return new Promise((resolve) => {
    let settled = false;
    const fail = (error) => { if (settled) return; settled = true; sock.destroy(); resolve({ target: host, port, reachable: false, error, findings: [] }); };
    const sock = net.connect({ host, port });
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => sock.write(ANON_BIND));
    sock.on('data', (buf) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      // bindResponse: ... 0x61 <len> 0x0a 0x01 <resultCode>
      const idx = buf.indexOf(0x61);
      if (idx === -1 || idx + 4 >= buf.length) {
        return resolve({ target: host, port, reachable: true, isLDAP: false, note: 'no bindResponse parsed', findings: [] });
      }
      const resultCode = buf[idx + 4];
      const findings = [];
      if (resultCode === 0) {
        findings.push({ severity: 'medium', message: 'LDAP accepts anonymous bind — directory may be enumerable without credentials' });
      }
      resolve({
        target: host, port, reachable: true, isLDAP: true,
        anonymousBind: resultCode === 0,
        resultCode, result: RESULT[resultCode] || `code ${resultCode}`,
        findings,
      });
    });
    sock.on('timeout', () => fail('timeout'));
    sock.on('error', (e) => fail(e.code || e.message));
    sock.on('close', () => { if (!settled) fail('closed before bind response'); });
  });
}
