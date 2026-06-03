/**
 * Protocol-parser tests. Each binary probe is exercised against a synthetic
 * localhost server returning a canned response, so the hand-rolled packet parsing
 * (SMB2 / SSH KEXINIT / RDP X.224 / LDAP BER / MySQL handshake / Postgres / SNMP
 * ASN.1) is covered without touching the network. Run with `node --test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import dgram from 'node:dgram';

import { smbProbe } from '../extensions/smb/src/smb.js';
import { sshAudit } from '../extensions/ssh/src/ssh.js';
import { rdpProbe } from '../extensions/rdp/src/rdp.js';
import { ldapProbe } from '../extensions/ldap/src/ldap.js';
import { mysqlProbe } from '../extensions/mysql/src/mysql.js';
import { postgresProbe } from '../extensions/postgres/src/postgres.js';
import { snmpProbe } from '../extensions/snmp/src/snmp.js';

// Spin a TCP server, run a probe against it, tear it down.
function withTcp(onSocket, probe, port0 = 0) {
  return new Promise((resolve) => {
    const srv = net.createServer(onSocket);
    srv.listen(port0, '127.0.0.1', async () => {
      const r = await probe('127.0.0.1', { port: srv.address().port, timeoutMs: 3000 });
      srv.close(); resolve(r);
    });
  });
}

test('smb.probe parses dialect + signing and flags missing signing', async () => {
  const smb = Buffer.alloc(64 + 8);
  smb.write('\xfeSMB', 0, 'latin1');
  smb.writeUInt16LE(64, 4); smb.writeUInt32LE(0, 8);            // status OK
  smb.subarray(64).writeUInt16LE(65, 0);                        // StructureSize
  smb.subarray(64).writeUInt16LE(0x0001, 2);                    // SIGNING_ENABLED only
  smb.subarray(64).writeUInt16LE(0x0311, 4);                    // dialect SMB 3.1.1
  const nb = Buffer.alloc(4); nb.writeUIntBE(smb.length, 1, 3);
  const r = await withTcp(s => s.on('data', () => s.write(Buffer.concat([nb, smb]))), smbProbe);
  assert.equal(r.dialect, 'SMB 3.1.1');
  assert.equal(r.signingRequired, false);
  assert.ok(r.findings.some(f => /signing not required/i.test(f.message)));
});

test('ssh.audit parses KEXINIT and flags weak algorithms', async () => {
  const nl = s => { const b = Buffer.from(s, 'ascii'); const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]); };
  const payload = Buffer.concat([
    Buffer.from([20]), Buffer.alloc(16),                        // KEXINIT + cookie
    nl('diffie-hellman-group14-sha1'), nl('ssh-rsa'),
    nl('aes128-cbc'), nl('aes128-cbc'),
    nl('hmac-sha1'), nl('hmac-sha1'),
    nl('none'), nl('none'), nl(''), nl(''),
    Buffer.from([0]), Buffer.alloc(4),
  ]);
  let pad = 8 - ((payload.length + 5) % 8); if (pad < 4) pad += 8;
  const pktLen = 1 + payload.length + pad;
  const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32BE(pktLen);
  const pkt = Buffer.concat([lenBuf, Buffer.from([pad]), payload, Buffer.alloc(pad)]);
  const r = await withTcp(s => s.write(Buffer.concat([Buffer.from('SSH-2.0-test\r\n'), pkt])), sshAudit);
  assert.equal(r.banner, 'SSH-2.0-test');
  assert.ok(r.weak.cipher.includes('aes128-cbc'));
  assert.ok(r.weak.kex.includes('diffie-hellman-group14-sha1'));
  assert.ok(r.findings.some(f => /weak ssh ciphers/i.test(f.message)));
});

test('rdp.probe flags Standard Security (no NLA)', async () => {
  const resp = Buffer.from([0x03, 0, 0, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
  const r = await withTcp(s => s.on('data', () => s.write(resp)), rdpProbe);
  assert.equal(r.security, 'Standard RDP Security');
  assert.equal(r.nla, false);
  assert.ok(r.findings.some(f => /NLA/.test(f.message)));
});

test('ldap.probe detects an accepted anonymous bind', async () => {
  // bindResponse: 30 0c 02 01 01 61 07 0a 01 00 04 00 04 00
  const resp = Buffer.from([0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]);
  const r = await withTcp(s => s.on('data', () => s.write(resp)), ldapProbe);
  assert.equal(r.isLDAP, true);
  assert.equal(r.anonymousBind, true);
  assert.ok(r.findings.some(f => /anonymous bind/i.test(f.message)));
});

test('mysql.probe reads the server version from the handshake', async () => {
  const hs = Buffer.concat([Buffer.from([0x4a, 0, 0, 0]), Buffer.from([10]), Buffer.from('8.0.36\0', 'latin1'), Buffer.alloc(20)]);
  const r = await withTcp(s => s.write(hs), mysqlProbe);
  assert.equal(r.isMySQL, true);
  assert.equal(r.serverVersion, '8.0.36');
});

test('postgres.probe detects a listener and no-SSL', async () => {
  const r = await withTcp(s => s.on('data', () => s.write(Buffer.from('N'))), postgresProbe);
  assert.equal(r.isPostgres, true);
  assert.equal(r.sslSupported, false);
  assert.ok(r.findings.some(f => /SSL/i.test(f.message)));
});

test('snmp.probe parses a GetResponse (ASN.1/BER)', async () => {
  // SNMPv2c GetResponse for sysDescr.0 = "test".
  const resp = Buffer.from([
    0x30, 0x2a, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
    0xa2, 0x1d, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
    0x30, 0x12, 0x30, 0x10, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
    0x04, 0x04, 0x74, 0x65, 0x73, 0x74,
  ]);
  const srv = dgram.createSocket('udp4');
  await new Promise(r => srv.bind(0, '127.0.0.1', r));
  srv.on('message', (msg, rinfo) => srv.send(resp, rinfo.port, rinfo.address));
  const out = await snmpProbe('127.0.0.1', { port: srv.address().port, communities: ['public'], timeoutMs: 3000 });
  srv.close();
  assert.equal(out.exposed, true);
  assert.equal(out.sysDescr, 'test');
});
