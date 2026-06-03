/**
 * Pivot engine — the "next best action" intelligence.
 *
 * Given an assessment's accumulated entity graph and the executors already run,
 * propose the next executors to run, ranked. This is what turns a pile of tools
 * into an investigation: a discovered subdomain queues a web/TLS sweep on it; an
 * open 445 queues `smb.probe`; an unscored CVE queues `vuln.epss`; and so on. The
 * agent reads the ranked list and decides — or just runs the top N.
 *
 * Pure over (session, catalog): no side effects, no I/O.
 */

import { hasRun } from './assessment.js';

// Recon to run against the primary target, by target type. Ordered passive-first.
const SEED = {
  domain: [
    ['dns.resolve', 85, 'resolve the domain'],
    ['rdap.lookup', 80, 'registration data'],
    ['whois.lookup', 78, 'registration data'],
    ['subdomains.passive', 84, 'enumerate subdomains (crt.sh)'],
    ['cert.ctlog', 80, 'certificate-transparency history'],
    ['email.security', 76, 'email auth posture'],
    ['dns.dnssec', 70, 'DNSSEC posture'], ['dns.caa', 68, 'CAA policy'],
    ['dns.txt_fingerprint', 70, 'SaaS footprint'], ['web.wayback', 66, 'archived URLs'],
    ['dns.zone_transfer', 64, 'AXFR attempt'],
    ['http.headers', 58, 'HTTP surface'], ['http.security_score', 58, 'header grade'],
    ['http.fingerprint', 56, 'tech stack'], ['http.waf_detect', 54, 'WAF/CDN'],
    ['tls.inspect', 56, 'certificate'], ['tls.deep', 52, 'deep TLS'],
    ['http.cors_check', 48, 'CORS'], ['http.methods', 48, 'HTTP methods'],
    ['http.cookies', 46, 'cookie flags'], ['http.robots', 50, 'robots/sitemap'],
    ['http.graphql', 46, 'GraphQL surface'], ['http.subdomain_takeover', 50, 'takeover check'],
    ['web.security_txt', 48, 'security.txt'], ['web.well_known', 46, 'well-known URIs'],
    ['http.favicon_hash', 44, 'favicon pivot'], ['nmap.scan', 60, 'port scan'],
    ['network.ping', 40, 'liveness'], ['shodan.host', 62, 'Shodan host data'],
    ['http.git_leak', 44, '.git exposure'], ['http.secrets', 42, 'exposed secrets'],
    ['http.fuzz_paths', 38, 'path fuzzing'], ['cloud.bucket_finder', 44, 'public buckets'],
    ['nuclei.scan', 64, 'templated vuln scan'],
  ],
  ip: [
    ['rdap.lookup', 80, 'IP registration'], ['dns.reverse', 78, 'reverse DNS'],
    ['nmap.scan', 76, 'port scan'], ['network.ping', 50, 'liveness'],
    ['network.traceroute', 44, 'path'], ['shodan.host', 74, 'Shodan host data'],
    ['censys.host', 72, 'Censys host data'], ['ip.intel', 70, 'ASN / abuse intel'],
    ['nuclei.scan', 60, 'templated vuln scan'],
  ],
};

// Service probes keyed by discovered open port number.
const PORT_PROBES = {
  21: [['network.banner', 70, 'FTP banner']],
  22: [['ssh.audit', 88, 'SSH algorithm audit']],
  25: [['smtp.probe', 84, 'SMTP STARTTLS/AUTH']],
  53: [['dns.resolve', 50, 'DNS server']],
  80: [['http.headers', 64, 'HTTP surface'], ['http.security_score', 62, 'header grade'], ['http.fingerprint', 58, 'tech']],
  161: [['snmp.probe', 86, 'SNMP community probe']],
  389: [['ldap.probe', 84, 'LDAP anonymous-bind check']],
  443: [['tls.inspect', 64, 'certificate'], ['http.security_score', 62, 'header grade'], ['tls.deep', 58, 'deep TLS']],
  445: [['smb.probe', 88, 'SMB signing posture']],
  636: [['ldap.probe', 84, 'LDAPS anonymous-bind check']],
  3306: [['mysql.probe', 80, 'MySQL handshake']],
  3389: [['rdp.probe', 86, 'RDP security / NLA check']],
  5432: [['postgres.probe', 80, 'PostgreSQL SSLRequest']],
  6379: [['network.banner', 64, 'Redis banner']],
};

// Web sweep to run against a freshly-discovered subdomain.
const SUBDOMAIN_WEB = [
  ['dns.resolve', 60, 'resolve'], ['http.headers', 56, 'HTTP surface'],
  ['http.security_score', 54, 'header grade'], ['http.fingerprint', 50, 'tech'],
  ['tls.inspect', 52, 'certificate'], ['http.subdomain_takeover', 58, 'takeover check'],
];

const URL_PROBES = [
  ['http.get', 54, 'fetch'], ['http.security_score', 50, 'header grade'], ['http.secrets', 56, 'exposed secrets'],
];

/**
 * Propose the next executors to run, ranked by priority (desc).
 *
 * @param session   the assessment
 * @param catalog   the loaded catalog
 * @param opts.posture   'passive' to restrict to passive executors
 * @param opts.limit     max suggestions (default 20)
 * @returns Suggestion[] — { uses, target, opts, reason, priority }
 */
export function suggest(session, catalog, { posture, limit = 20 } = {}) {
  const effPosture = posture || session.posture;
  const meta = new Map(catalog.executors.map(e => [e.uses, e]));
  const out = [];
  const seen = new Set();

  const push = (uses, target, reason, priority, opts = {}) => {
    const m = meta.get(uses);
    if (!m) return;                                   // executor not installed
    if (effPosture === 'passive' && m.posture !== 'passive') return;
    if (hasRun(session, uses, target)) return;        // already done
    const key = `${uses}@${target}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ uses, target, opts, reason, priority, phase: m.phase, posture: m.posture });
  };

  // 1. Seed recon on the primary target.
  const seed = SEED[session.targetType === 'url' ? 'domain' : session.targetType] || SEED.domain;
  for (const [uses, prio, reason] of seed) push(uses, session.target, reason, prio);

  // 2. Entity-driven pivots.
  for (const e of session.entities) {
    if (e.scanned) continue;
    const v = e.value;
    if (e.type === 'subdomain' && v !== session.target) {
      for (const [uses, prio, reason] of SUBDOMAIN_WEB) push(uses, v, `${reason} — discovered subdomain`, prio);
    } else if (e.type === 'ip') {
      for (const [uses, prio, reason] of SEED.ip) push(uses, v, `${reason} — discovered IP`, prio - 5);
    } else if (e.type === 'port') {
      const probes = PORT_PROBES[e.attrs?.number] || [];
      const host = e.attrs?.host || session.target;
      for (const [uses, prio, reason] of probes) push(uses, host, `${reason} — ${e.value} open on ${host}`, prio);
    } else if (e.type === 'url') {
      for (const [uses, prio, reason] of URL_PROBES) push(uses, v, `${reason} — discovered URL`, prio);
    } else if (e.type === 'cve' && !e.attrs?.scored) {
      push('vuln.epss', session.target, `score exploit probability for ${v}`, 75, { cve: v });
    } else if (e.type === 'tech' && e.attrs?.version) {
      push('vuln.cve_lookup', session.target, `CVE lookup for ${v} ${e.attrs.version}`, 42, { product: String(v), version: String(e.attrs.version) });
    }
  }

  out.sort((a, b) => b.priority - a.priority || a.uses.localeCompare(b.uses));
  return out.slice(0, limit);
}
