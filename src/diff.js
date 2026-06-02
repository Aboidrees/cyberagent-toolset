import fs from 'fs/promises';
import { extractFindings } from './utils/findings.js';

/**
 * Diff reports — compare two run JSON files for the same target and highlight
 * what changed: new/removed open ports, subdomains, DNS records, certificate
 * changes, and new/resolved security findings.
 */

/** Pull comparable facts out of a run report. */
function extractFacts(report) {
  const facts = {
    target: report?.vars?.target || null,
    when: report?.endedAt || report?.startedAt || null,
    ports: new Set(),
    subdomains: new Set(),
    dns: new Set(),
    certs: {},
    findings: new Set(),
  };

  for (const o of report?.outputs || []) {
    if (!o || !o.ok || !o.data) continue;
    const d = o.data;

    // Open ports from nmap raw output: lines like "80/tcp open http".
    if (o.uses === 'nmap.scan' && typeof d.raw === 'string') {
      for (const m of d.raw.matchAll(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)?/gim)) {
        facts.ports.add(`${m[1]}/${m[2]}${m[3] ? ` (${m[3]})` : ''}`);
      }
    }

    // Subdomains.
    if (o.uses === 'subdomains.passive' && Array.isArray(d.merged)) {
      for (const s of d.merged) facts.subdomains.add(s);
    }

    // DNS records.
    if (o.uses === 'dns.resolve' && d && typeof d === 'object') {
      for (const [type, vals] of Object.entries(d)) {
        if (Array.isArray(vals)) for (const v of vals) facts.dns.add(`${type}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
      }
    }

    // TLS certificate identity (expiry + fingerprint).
    if (o.uses === 'tls.inspect' && d.cert) {
      facts.certs[`${d.servername || facts.target}:${d.port || 443}`] = {
        valid_to: d.cert.valid_to || null,
        fingerprint256: d.cert.fingerprint256 || null,
        issuer: d.cert.issuer?.O || null,
      };
    }
  }

  for (const f of extractFindings(report)) facts.findings.add(`${f.severity}|${f.message}`);
  return facts;
}

/** Set difference → { added, removed } as sorted arrays. */
function setDiff(a, b) {
  const added = [...b].filter(x => !a.has(x)).sort();
  const removed = [...a].filter(x => !b.has(x)).sort();
  return { added, removed };
}

/**
 * Compare two run reports (objects). Returns a structured diff.
 */
export function diffRuns(reportA, reportB) {
  const a = extractFacts(reportA);
  const b = extractFacts(reportB);

  // Certificate changes (by host:port present in either run).
  const certHosts = new Set([...Object.keys(a.certs), ...Object.keys(b.certs)]);
  const certChanges = [];
  for (const host of certHosts) {
    const ca = a.certs[host];
    const cb = b.certs[host];
    if (ca && cb && ca.fingerprint256 !== cb.fingerprint256) {
      certChanges.push({ host, change: 'certificate rotated', from: ca, to: cb });
    } else if (ca && cb && ca.valid_to !== cb.valid_to) {
      certChanges.push({ host, change: 'validity changed', from: ca.valid_to, to: cb.valid_to });
    } else if (!ca && cb) {
      certChanges.push({ host, change: 'certificate appeared', to: cb });
    } else if (ca && !cb) {
      certChanges.push({ host, change: 'certificate disappeared', from: ca });
    }
  }

  return {
    target: b.target || a.target,
    from: { when: a.when },
    to: { when: b.when },
    ports: setDiff(a.ports, b.ports),
    subdomains: setDiff(a.subdomains, b.subdomains),
    dns: setDiff(a.dns, b.dns),
    findings: setDiff(a.findings, b.findings),
    certs: certChanges,
  };
}

/** Did anything actually change? */
export function hasChanges(diff) {
  return (
    diff.ports.added.length || diff.ports.removed.length ||
    diff.subdomains.added.length || diff.subdomains.removed.length ||
    diff.dns.added.length || diff.dns.removed.length ||
    diff.findings.added.length || diff.findings.removed.length ||
    diff.certs.length
  ) > 0;
}

/** Render a diff as Markdown. */
export function formatDiffMarkdown(diff) {
  const lines = [
    `# Diff Report — ${diff.target || 'unknown'}`,
    `- From: ${diff.from.when || '?'}`,
    `- To: ${diff.to.when || '?'}`,
    '',
  ];
  if (!hasChanges(diff)) {
    lines.push('No changes detected between the two runs.');
    return lines.join('\n');
  }

  const section = (title, d, addLabel = 'New', remLabel = 'Removed') => {
    if (!d.added.length && !d.removed.length) return;
    lines.push(`## ${title}`, '');
    for (const x of d.added) lines.push(`- 🟢 **${addLabel}:** ${x}`);
    for (const x of d.removed) lines.push(`- 🔴 **${remLabel}:** ${x}`);
    lines.push('');
  };

  section('Open Ports', diff.ports);
  section('Subdomains', diff.subdomains);
  section('DNS Records', diff.dns);
  section('Security Findings', diff.findings, 'New finding', 'Resolved');

  if (diff.certs.length) {
    lines.push('## Certificates', '');
    for (const c of diff.certs) {
      lines.push(`- ⚠️ **${c.host}:** ${c.change}` +
        (c.from && c.to ? ` (${JSON.stringify(c.from)} → ${JSON.stringify(c.to)})` : ''));
    }
    lines.push('');
  }

  return lines.join('\n');
}

/** Load + diff two run JSON files by path. */
export async function diffFiles(pathA, pathB) {
  const [a, b] = await Promise.all([
    fs.readFile(pathA, 'utf8').then(JSON.parse),
    fs.readFile(pathB, 'utf8').then(JSON.parse),
  ]);
  return diffRuns(a, b);
}
