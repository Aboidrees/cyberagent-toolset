import dgram from 'dgram';
import { validateTarget } from '#sdk';

/**
 * SNMP exposure probe. SNMP (UDP/161) on a default/guessable community string is
 * a classic information-disclosure foothold — it leaks the system description,
 * and with write communities, configuration. This sends a read-only SNMPv2c GET
 * for sysDescr.0 with each candidate community and reports which (if any) answer.
 * Read-only: a single GET per community, no SET. Keyless.
 */

const SYS_DESCR = '1.3.6.1.2.1.1.1.0';
const DEFAULT_COMMUNITIES = ['public', 'private', 'community', 'manager'];

// ── minimal ASN.1/BER encoding ───────────────────────────────────────────────
function encodeLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let x = n;
  while (x > 0) { bytes.unshift(x & 0xff); x >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag, value) {
  return Buffer.concat([Buffer.from([tag]), encodeLen(value.length), value]);
}
function encInt(n) {
  const bytes = [];
  let x = n;
  if (x === 0) bytes.push(0);
  else { while (x > 0) { bytes.unshift(x & 0xff); x >>= 8; } if (bytes[0] & 0x80) bytes.unshift(0); }
  return tlv(0x02, Buffer.from(bytes));
}
function encStr(s) { return tlv(0x04, Buffer.from(s, 'latin1')); }
function encOid(oid) {
  const parts = oid.split('.').map(Number);
  const bytes = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    if (v < 0x80) { bytes.push(v); continue; }
    const stack = [v & 0x7f];
    v >>= 7;
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v >>= 7; }
    bytes.push(...stack);
  }
  return tlv(0x06, Buffer.from(bytes));
}

function buildGet(community, reqId) {
  const varbind = tlv(0x30, Buffer.concat([encOid(SYS_DESCR), Buffer.from([0x05, 0x00])]));
  const varbindList = tlv(0x30, varbind);
  const pdu = tlv(0xa0, Buffer.concat([encInt(reqId), encInt(0), encInt(0), varbindList]));
  return tlv(0x30, Buffer.concat([encInt(1), encStr(community), pdu])); // version 1 = v2c
}

// ── minimal BER walk to extract error-status + first varbind value ────────────
function readTLV(buf, pos) {
  const tag = buf[pos];
  let len = buf[pos + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[pos + 2 + i];
    hdr = 2 + n;
  }
  return { tag, len, value: buf.subarray(pos + hdr, pos + hdr + len), end: pos + hdr + len };
}

function parseResponse(buf) {
  try {
    const seq = readTLV(buf, 0);               // outer SEQUENCE
    let p = 0;
    const version = readTLV(seq.value, p); p = version.end;
    const community = readTLV(seq.value, p); p = community.end;
    const pdu = readTLV(seq.value, p);         // 0xa2 = GetResponse
    if (pdu.tag !== 0xa2) return { ok: false };
    let q = 0;
    const reqId = readTLV(pdu.value, q); q = reqId.end;
    const errStatus = readTLV(pdu.value, q); q = errStatus.end;
    const errIndex = readTLV(pdu.value, q); q = errIndex.end;
    const vbl = readTLV(pdu.value, q);
    const vb = readTLV(vbl.value, 0);
    let r = 0;
    const oid = readTLV(vb.value, r); r = oid.end;
    const val = readTLV(vb.value, r);
    const error = errStatus.value.length ? errStatus.value[errStatus.value.length - 1] : 0;
    const sysDescr = val.tag === 0x04 ? val.value.toString('latin1') : null;
    return { ok: error === 0 && val.tag !== 0x80, error, sysDescr };
  } catch {
    return { ok: false };
  }
}

function probeCommunity(host, port, community, timeoutMs) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    let done = false;
    const finish = (res) => { if (done) return; done = true; try { sock.close(); } catch { /* noop */ } resolve(res); };
    const timer = setTimeout(() => finish({ community, responded: false }), timeoutMs);
    timer.unref?.();
    sock.on('message', (msg) => {
      clearTimeout(timer);
      const parsed = parseResponse(msg);
      finish({ community, responded: parsed.ok, sysDescr: parsed.sysDescr || null });
    });
    sock.on('error', () => { clearTimeout(timer); finish({ community, responded: false }); });
    const pkt = buildGet(community, 1000 + Math.floor(timeoutMs % 1000));
    sock.send(pkt, port, host, (err) => { if (err) { clearTimeout(timer); finish({ community, responded: false }); } });
  });
}

export async function snmpProbe(target, opts = {}) {
  const host = validateTarget(target);
  const port = opts.port || 161;
  const timeoutMs = opts.timeoutMs || 4000;
  const communities = Array.isArray(opts.communities) && opts.communities.length
    ? opts.communities.map(String)
    : DEFAULT_COMMUNITIES;

  const results = [];
  for (const c of communities) {
    results.push(await probeCommunity(host, port, c, timeoutMs));
  }
  const open = results.filter(r => r.responded);
  const findings = open.map(r => ({
    severity: 'high',
    message: `SNMP responds to community "${r.community}"${r.sysDescr ? ` — ${r.sysDescr.slice(0, 120)}` : ''}`,
  }));

  return {
    target: host, port,
    communitiesTried: communities,
    open: open.map(r => r.community),
    sysDescr: open.find(r => r.sysDescr)?.sysDescr || null,
    exposed: open.length > 0,
    findings,
  };
}
