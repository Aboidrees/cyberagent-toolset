/**
 * Pure-function unit tests — no network. Covers the security-critical input
 * validation, the auth-header builder, entity extraction, the pivot engine, and
 * report synthesis. Run with `node --test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { validateTarget } from '../src/utils/validate.js';
import { buildUrl, authHeaders } from '../extensions/web/src/http.js';
import { extractEntities, entityKey } from '../src/entities.js';
import { suggest } from '../src/pivots.js';
import { createAssessment, runStep, preflightTarget } from '../src/assessment.js';
import { synthesize } from '../src/assessment-report.js';
import { loadCatalog } from '../src/extensions/loader.js';

// ── validateTarget (security: command-injection guard) ────────────────────────
test('validateTarget accepts hostnames, IPs, CIDR', () => {
  for (const t of ['example.com', 'a.b.example.co.uk', '1.2.3.4', '192.168.0.0/24', 'localhost']) {
    assert.equal(validateTarget(t), t);
  }
});
test('validateTarget rejects shell metacharacters and injection', () => {
  // Embedded control chars / metacharacters must be rejected (trailing whitespace
  // is trimmed to a safe value, so test an *embedded* newline, not a trailing one).
  for (const bad of ['a.com; rm -rf /', 'a.com && id', 'a.com|cat', '$(whoami)', 'a.com`id`', 'a com', 'a\ncom', 'a\tb.com', '']) {
    assert.throws(() => validateTarget(bad), `should reject ${JSON.stringify(bad)}`);
  }
});

// ── buildUrl (security: SSRF / host-override guard) ───────────────────────────
test('buildUrl builds a clean URL and whitelists the scheme', () => {
  assert.equal(buildUrl('https', 'example.com', '/x'), 'https://example.com/x');
  assert.equal(buildUrl('ftp', 'example.com', '/x'), 'https://example.com/x'); // non-http(s) → https
  assert.equal(buildUrl('http', 'example.com', 'y'), 'http://example.com/y');  // adds leading slash
});
test('buildUrl rejects credential / protocol-relative / control-char paths', () => {
  for (const p of ['/@evil.com', '//evil.com', '/a b', '/a\\b', '/a\x00b']) {
    assert.throws(() => buildUrl('https', 'example.com', p), `should reject path ${JSON.stringify(p)}`);
  }
});

// ── authHeaders ───────────────────────────────────────────────────────────────
test('authHeaders builds bearer / basic / cookie / extra headers', () => {
  assert.deepEqual(authHeaders({ bearer: 'tok' }), { Authorization: 'Bearer tok' });
  assert.deepEqual(authHeaders({ basic: 'u:p' }), { Authorization: 'Basic ' + Buffer.from('u:p').toString('base64') });
  assert.deepEqual(authHeaders({ cookie: 'sid=1' }), { Cookie: 'sid=1' });
  assert.equal(authHeaders({ bearer: 't', headers: { 'X-Test': '1' } })['X-Test'], '1');
  assert.deepEqual(authHeaders({}), {});
});

// ── extractEntities ───────────────────────────────────────────────────────────
test('extractEntities pulls IPs/NS/MX from dns.resolve', () => {
  const ents = extractEntities('dns.resolve', 'x.com', { A: ['1.2.3.4'], NS: ['ns1.x.com.'], MX: [{ exchange: 'mail.x.com' }] });
  const types = ents.map(e => `${e.type}:${e.value}`);
  assert.ok(types.includes('ip:1.2.3.4'));
  assert.ok(types.includes('nameserver:ns1.x.com'));
  assert.ok(types.includes('mailhost:mail.x.com'));
});
test('extractEntities pulls subdomains and nmap ports', () => {
  assert.equal(extractEntities('subdomains.passive', 'x.com', { merged: ['a.x.com', 'b.x.com'] }).length, 2);
  const ports = extractEntities('nmap.scan', 'x.com', { raw: '80/tcp open http\n443/tcp open ssl/https\n' });
  assert.deepEqual(ports.map(e => e.value).sort(), ['443/tcp', '80/tcp']);
  assert.equal(ports.find(e => e.value === '80/tcp').attrs.service, 'http');
});
test('extractEntities scores CVEs from vuln.epss and sweeps finding messages', () => {
  const epss = extractEntities('vuln.epss', 'x.com', { results: [{ cve: 'CVE-2021-44228', epss: 0.9 }] });
  assert.equal(epss[0].type, 'cve');
  assert.equal(epss[0].attrs.scored, true);
  const swept = extractEntities('nuclei.scan', 'x.com', { findings: [{ message: 'matched CVE-2020-1234 here' }] });
  assert.ok(swept.some(e => e.type === 'cve' && e.value === 'CVE-2020-1234'));
});
test('entityKey is stable and case-insensitive', () => {
  assert.equal(entityKey({ type: 'subdomain', value: 'A.X.com' }), entityKey({ type: 'subdomain', value: 'a.x.com' }));
});

// ── pivot engine ──────────────────────────────────────────────────────────────
test('suggest seeds recon, filters by posture, dedups run steps, maps ports', async () => {
  const catalog = await loadCatalog();
  const s = createAssessment({ target: 'x.com' });

  const all = suggest(s, catalog, {});
  assert.ok(all.length > 0, 'proposes actions');
  assert.ok(all.every((a, i) => i === 0 || all[i - 1].priority >= a.priority), 'ranked desc');

  const passive = suggest(s, catalog, { posture: 'passive' });
  assert.ok(passive.every(a => a.posture === 'passive'), 'passive filter');

  // Dedup: a (uses,target) already run is not re-suggested.
  s.steps.push({ uses: 'dns.resolve', target: 'x.com' });
  assert.ok(!suggest(s, catalog, {}).some(a => a.uses === 'dns.resolve' && a.target === 'x.com'));

  // Port pivot: a discovered open 445 queues smb.probe on its host.
  s.entities.push({ type: 'port', value: '445/tcp', attrs: { number: 445, host: 'x.com' }, source: 'nmap.scan', scanned: false });
  assert.ok(suggest(s, catalog, {}).some(a => a.uses === 'smb.probe' && a.target === 'x.com'));
});

// ── report synthesis + diagnostics ────────────────────────────────────────────
test('synthesize correlates CVEs by EPSS and counts severities', () => {
  const s = createAssessment({ target: 'x.com' });
  s.reachability = { resolves: true, addresses: ['1.2.3.4'], reason: 'resolved' };
  s.findings = [{ severity: 'high', message: 'h', uses: 'x', target: 'x.com' }, { severity: 'low', message: 'l', uses: 'x', target: 'x.com' }];
  s.entities.push({ type: 'cve', value: 'CVE-1', attrs: { epss: 0.95, cvss: 9 }, source: 'vuln.epss' });
  s.entities.push({ type: 'cve', value: 'CVE-2', attrs: { epss: 0.2 }, source: 'vuln.epss' });
  const { json } = synthesize(s);
  assert.equal(json.severityCounts.high, 1);
  assert.equal(json.cves[0].cve, 'CVE-1', 'highest EPSS first');
  assert.ok(json.topRisks.some(r => r.message.includes('CVE-1')), 'high-EPSS CVE is a top risk');
});
test('synthesize emits an explicit diagnostic for an unresolvable target', () => {
  const s = createAssessment({ target: 'nope.invalid' });
  s.reachability = { resolves: false, addresses: [], reason: 'ENOTFOUND' };
  s.steps.push({ uses: 'dns.resolve', target: 'nope.invalid', ok: true });
  const { json } = synthesize(s);
  assert.ok(json.diagnostics.some(d => /ENOTFOUND/.test(d)), 'diagnostic names ENOTFOUND');
});

// ── preflight ─────────────────────────────────────────────────────────────────
test('preflightTarget marks an IP literal reachable without DNS', async () => {
  const s = createAssessment({ target: '8.8.8.8' });
  const r = await preflightTarget(s);
  assert.equal(r.resolves, true);
  assert.equal(r.reason, 'ip-literal');
});

// keep runStep referenced (used by integration paths) without a network call
test('runStep rejects an unknown executor', async () => {
  const catalog = await loadCatalog();
  const s = createAssessment({ target: 'x.com' });
  await assert.rejects(() => runStep(s, { uses: 'does.not.exist', target: 'x.com' }, catalog));
});
