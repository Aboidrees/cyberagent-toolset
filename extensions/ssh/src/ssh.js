import net from 'net';
import { validateTarget } from '#sdk';

/**
 * SSH algorithm audit. Connects, reads the server identification banner, and
 * parses the SSH_MSG_KEXINIT packet to enumerate the offered key-exchange,
 * host-key, cipher, and MAC algorithms — then flags weak/deprecated ones. No
 * authentication is attempted; this only reads what the server advertises during
 * the protocol handshake. Implemented over a raw socket (no ssh2 dependency).
 */

const CLIENT_ID = 'SSH-2.0-recon-probe\r\n';

// Weak / deprecated algorithm matchers (substring or exact, case-insensitive).
const WEAK = {
  kex: [/^diffie-hellman-group1-sha1$/, /^diffie-hellman-group14-sha1$/, /sha1$/, /^gss-/, /-sha1$/],
  hostKey: [/^ssh-rsa$/, /^ssh-dss$/, /^rsa-sha2-256-cert/, /-cert-v00@/],
  cipher: [/cbc/, /^arcfour/, /^3des/, /^blowfish/, /^cast128/, /^none$/, /^des/],
  mac: [/^hmac-md5/, /^hmac-sha1$/, /^hmac-sha1-96/, /-96$/, /^umac-64/],
};

function flagWeak(list, matchers) {
  return (list || []).filter(a => matchers.some(re => re.test(a.toLowerCase())));
}

/** Read a length-prefixed SSH name-list at offset; returns { list, next }. */
function readNameList(buf, offset) {
  if (offset + 4 > buf.length) return { list: [], next: offset + 4 };
  const len = buf.readUInt32BE(offset);
  const start = offset + 4;
  const str = buf.toString('ascii', start, start + len);
  return { list: str ? str.split(',') : [], next: start + len };
}

/** Parse a KEXINIT payload (starts with msg code 20). */
function parseKexinit(payload) {
  if (payload[0] !== 20) return null;
  let pos = 1 + 16; // skip msg code + 16-byte cookie
  const fields = [
    'kex', 'serverHostKey',
    'encClientToServer', 'encServerToClient',
    'macClientToServer', 'macServerToClient',
    'compClientToServer', 'compServerToClient',
    'langClientToServer', 'langServerToClient',
  ];
  const out = {};
  for (const f of fields) {
    const { list, next } = readNameList(payload, pos);
    out[f] = list;
    pos = next;
  }
  return out;
}

/** Extract the server ID line and the first binary packet payload from the stream. */
function extractHandshake(buf) {
  // Server may emit pre-auth banner lines; the ID is the line starting "SSH-".
  let idLineEnd = -1, idLine = null;
  let scan = 0;
  while (scan < buf.length) {
    let nl = buf.indexOf(0x0a, scan);
    if (nl === -1) break;
    const line = buf.toString('ascii', scan, nl).replace(/\r$/, '');
    if (line.startsWith('SSH-')) { idLine = line; idLineEnd = nl + 1; break; }
    scan = nl + 1;
  }
  if (!idLine || idLineEnd === -1) return { needMore: true };

  const rest = buf.subarray(idLineEnd);
  if (rest.length < 5) return { idLine, needMore: true };
  const pktLen = rest.readUInt32BE(0);
  if (pktLen > 100000) return { idLine, error: 'implausible packet length' };
  if (rest.length < 4 + pktLen) return { idLine, needMore: true };
  const padLen = rest[4];
  const payload = rest.subarray(5, 5 + (pktLen - padLen - 1));
  return { idLine, payload };
}

export async function sshAudit(target, opts = {}) {
  const host = validateTarget(target);
  const port = opts.port || 22;
  const timeoutMs = opts.timeoutMs || 10000;

  return new Promise((resolve) => {
    const chunks = [];
    let settled = false;
    const done = (extra) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ target: host, port, reachable: true, ...extra });
    };
    const fail = (err) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ target: host, port, reachable: false, error: err, findings: [] });
    };

    const socket = net.connect({ host, port });
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => socket.write(CLIENT_ID));
    socket.on('data', (d) => {
      chunks.push(d);
      const buf = Buffer.concat(chunks);
      const hs = extractHandshake(buf);
      if (hs.needMore) return;
      if (hs.error) return done({ banner: hs.idLine, error: hs.error, findings: [] });

      const algos = hs.payload ? parseKexinit(hs.payload) : null;
      if (!algos) return done({ banner: hs.idLine, error: 'no KEXINIT parsed', findings: [] });

      const ciphers = [...new Set([...(algos.encServerToClient || []), ...(algos.encClientToServer || [])])];
      const macs = [...new Set([...(algos.macServerToClient || []), ...(algos.macClientToServer || [])])];

      const weak = {
        kex: flagWeak(algos.kex, WEAK.kex),
        hostKey: flagWeak(algos.serverHostKey, WEAK.hostKey),
        cipher: flagWeak(ciphers, WEAK.cipher),
        mac: flagWeak(macs, WEAK.mac),
      };
      const findings = [];
      if (weak.cipher.length) findings.push({ severity: 'medium', message: `Weak SSH ciphers offered: ${weak.cipher.join(', ')}` });
      if (weak.kex.length) findings.push({ severity: 'medium', message: `Weak SSH key-exchange offered: ${weak.kex.join(', ')}` });
      if (weak.mac.length) findings.push({ severity: 'low', message: `Weak SSH MACs offered: ${weak.mac.join(', ')}` });
      if (weak.hostKey.length) findings.push({ severity: 'low', message: `Weak SSH host-key algorithms: ${weak.hostKey.join(', ')}` });

      done({
        banner: hs.idLine,
        productVersion: hs.idLine.replace(/^SSH-\d+\.\d+-/, ''),
        kexAlgorithms: algos.kex,
        hostKeyAlgorithms: algos.serverHostKey,
        ciphers, macs,
        compression: [...new Set([...(algos.compServerToClient || []), ...(algos.compClientToServer || [])])],
        weak,
        findings,
      });
    });
    socket.on('timeout', () => fail('timeout'));
    socket.on('error', (e) => fail(e.code || e.message));
    socket.on('close', () => { if (!settled) fail('connection closed before handshake'); });
  });
}
