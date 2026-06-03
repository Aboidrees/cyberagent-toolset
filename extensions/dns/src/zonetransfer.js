import net from 'net';
import dns from 'dns/promises';
import { validateTarget } from '#sdk';

const QTYPE_AXFR = 252;
const RR_TYPES = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
  28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 43: 'DS', 46: 'RRSIG', 48: 'DNSKEY', 257: 'CAA',
};

/** Build an AXFR query message (no TCP length prefix). */
function buildAxfrQuery(domain) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1337, 0);        // id (fixed — single query)
  header.writeUInt16BE(0x0000, 2);        // flags: standard query, no recursion
  header.writeUInt16BE(1, 4);             // qdcount
  const labels = domain.split('.').filter(Boolean);
  const parts = [];
  for (const l of labels) {
    const b = Buffer.from(l, 'ascii');
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));           // root
  const qtail = Buffer.alloc(4);
  qtail.writeUInt16BE(QTYPE_AXFR, 0);     // qtype AXFR
  qtail.writeUInt16BE(1, 2);              // qclass IN
  return Buffer.concat([header, ...parts, qtail]);
}

/** Read a DNS name starting at offset, following compression pointers. */
function readName(buf, offset) {
  const labels = [];
  let pos = offset, jumped = false, end = offset, safety = 0;
  while (safety++ < 128 && pos < buf.length) {
    const len = buf[pos];
    if (len === 0) { pos++; if (!jumped) end = pos; break; }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) break;
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (!jumped) end = pos + 2;
      pos = ptr; jumped = true; continue;
    }
    labels.push(buf.toString('ascii', pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  return { name: labels.join('.'), next: jumped ? end : pos };
}

/** Parse one DNS message; return { rcode, ancount, records[] }. */
function parseMessage(buf) {
  if (buf.length < 12) return { rcode: -1, ancount: 0, records: [] };
  const flags = buf.readUInt16BE(2);
  const rcode = flags & 0x0f;
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  let pos = 12;
  for (let i = 0; i < qd; i++) { pos = readName(buf, pos).next + 4; } // skip questions
  const records = [];
  for (let i = 0; i < an && pos < buf.length; i++) {
    const nm = readName(buf, pos);
    pos = nm.next;
    if (pos + 10 > buf.length) break;
    const type = buf.readUInt16BE(pos);
    const rdlength = buf.readUInt16BE(pos + 8);
    pos += 10;
    records.push({ name: nm.name, type: RR_TYPES[type] || `TYPE${type}` });
    pos += rdlength;
  }
  return { rcode, ancount: an, records };
}

/** Attempt AXFR against a single nameserver IP. */
function axfrAttempt(nsIp, domain, timeoutMs) {
  return new Promise((resolve) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    const finish = (extra) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      const data = Buffer.concat(chunks);
      // TCP DNS frames each message with a 2-byte length prefix.
      const allRecords = [];
      let rcode = -1, p = 0;
      while (p + 2 <= data.length) {
        const mlen = data.readUInt16BE(p);
        if (p + 2 + mlen > data.length) break;
        const msg = data.subarray(p + 2, p + 2 + mlen);
        const parsed = parseMessage(msg);
        if (rcode === -1) rcode = parsed.rcode;
        allRecords.push(...parsed.records);
        p += 2 + mlen;
      }
      const allowed = allRecords.length > 0;
      resolve({ ns: nsIp, allowed, rcode, recordCount: allRecords.length, records: allRecords.slice(0, 50), ...extra });
    };

    const socket = net.connect({ host: nsIp, port: 53 });
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => {
      const q = buildAxfrQuery(domain);
      const framed = Buffer.alloc(2 + q.length);
      framed.writeUInt16BE(q.length, 0);
      q.copy(framed, 2);
      socket.write(framed);
    });
    socket.on('data', (d) => {
      chunks.push(d); total += d.length;
      if (total > 5_000_000) finish({ truncated: true });   // cap large zones
    });
    socket.on('end', () => finish());
    socket.on('close', () => finish());
    socket.on('timeout', () => finish({ timedOut: true }));
    socket.on('error', (e) => {
      if (settled) return;
      settled = true;
      resolve({ ns: nsIp, allowed: false, error: e.code || e.message, recordCount: 0, records: [] });
    });
  });
}

/**
 * Attempt a DNS zone transfer (AXFR) against each of the domain's authoritative
 * nameservers. A nameserver that answers an AXFR from an arbitrary client is a
 * serious misconfiguration — it discloses the entire zone (every record). Almost
 * all servers refuse; any that don't are flagged critical. Active recon.
 */
export async function zoneTransfer(target, opts = {}) {
  const domain = validateTarget(target);
  const timeoutMs = opts.timeoutMs || 8000;

  let nsNames = [];
  try {
    nsNames = await dns.resolveNs(domain);
  } catch (e) {
    return { target: domain, error: `Could not resolve NS records: ${e.code || e.message}`, nameservers: [], results: [], findings: [] };
  }
  if (!nsNames.length) {
    return { target: domain, error: 'No NS records found', nameservers: [], results: [], findings: [] };
  }

  const results = [];
  for (const ns of nsNames) {
    let ips = [];
    try { ips = await dns.resolve4(ns); } catch { /* skip unresolvable NS */ }
    if (!ips.length) {
      results.push({ ns, nameserver: ns, allowed: false, error: 'NS has no A record', recordCount: 0, records: [] });
      continue;
    }
    const r = await axfrAttempt(ips[0], domain, timeoutMs);
    results.push({ nameserver: ns, ...r });
  }

  const findings = results
    .filter(r => r.allowed)
    .map(r => ({
      severity: 'critical',
      message: `Zone transfer ALLOWED by ${r.nameserver} (${r.ns}) — ${r.recordCount} records disclosed`,
    }));

  return {
    target: domain,
    nameservers: nsNames,
    vulnerable: findings.length > 0,
    results,
    findings,
  };
}
