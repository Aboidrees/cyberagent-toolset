/**
 * Entity extraction.
 *
 * Mines an executor's structured result for *entities* — the concrete things a
 * recon assessment discovers (subdomains, IPs, open ports, URLs, emails, tech,
 * CVEs). Entities are what make findings chainable: the pivot engine
 * (`src/pivots.js`) turns newly-discovered entities into next-best actions, so
 * the agent can drive a recon tree (discover → pivot → scan → correlate) instead
 * of guessing which tool to call next.
 *
 * Mirrors the findings model: a per-`uses` extractor registry plus a generic
 * fallback. A misbehaving extractor must never throw out of `extractEntities`.
 */

const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

const ent = (type, value, attrs = {}) => ({ type, value: String(value), attrs });

/** Per-`uses` extractors. Each returns an array of entities (or []). */
const EXTRACTORS = {
  'dns.resolve': (t, d) => {
    const out = [];
    for (const ip of d.A || []) out.push(ent('ip', ip, { host: t }));
    for (const ip of d.AAAA || []) out.push(ent('ip', ip, { host: t, v6: true }));
    for (const ns of d.NS || []) out.push(ent('nameserver', String(ns).toLowerCase().replace(/\.$/, '')));
    for (const mx of d.MX || []) {
      const host = (mx.exchange || mx).toString().toLowerCase().replace(/\.$/, '');
      if (host) out.push(ent('mailhost', host));
    }
    return out;
  },
  'dns.reverse': (t, d) => (d.names || []).map(n => ent('subdomain', String(n).toLowerCase().replace(/\.$/, ''))),
  'subdomains.passive': (t, d) => (d.merged || []).map(s => ent('subdomain', String(s).toLowerCase())),
  'subdomains.bruteforce': (t, d) => (d.subdomains || []).flatMap(s => {
    const name = (s.subdomain || s).toString().toLowerCase();
    const out = [ent('subdomain', name)];
    for (const ip of s.addresses || []) out.push(ent('ip', ip, { host: name }));
    return out;
  }),
  'cert.ctlog': (t, d) => {
    const names = new Set([...(d.names || []), ...(d.certificates || []).map(c => c.commonName).filter(Boolean)]);
    return [...names]
      .map(n => String(n).toLowerCase().replace(/^\*\./, ''))
      .filter(n => n.endsWith(String(t).toLowerCase()))
      .map(n => ent('subdomain', n));
  },
  'rdap.lookup': (t, d) => {
    const out = (d.nameservers || []).map(n => ent('nameserver', String(n).toLowerCase()));
    if (d.abuseContact) out.push(ent('email', d.abuseContact));
    return out;
  },
  'hunter.emails': (t, d) => (d.emails || []).map(e => ent('email', e.value || e, { name: e.name, type: e.type })),
  'nmap.scan': (t, d) => parsePorts(d.raw, d.target || t),
  'network.banner': (t, d) => (d.open || d.results || [])
    .filter(r => r && r.open && r.port)
    .map(r => ent('port', `${r.port}/tcp`, { number: r.port, proto: 'tcp', host: t, banner: r.banner || null })),
  'smb.probe': (t, d) => d.reachable ? [ent('port', '445/tcp', { number: 445, proto: 'tcp', host: t, service: 'smb' })] : [],
  'snmp.probe': (t, d) => d.exposed ? [ent('port', '161/udp', { number: 161, proto: 'udp', host: t, service: 'snmp' })] : [],
  'http.fingerprint': (t, d) => (d.technologies || []).map(x => ent('tech', x.name || x, { category: x.category, version: x.version, host: t })),
  'http.headers': (t, d) => httpTech(t, d),
  'http.get': (t, d) => httpTech(t, d),
  'web.wayback': (t, d) => (d.urls || []).slice(0, 200).map(u => ent('url', typeof u === 'string' ? u : u.url || u.original)),
  'http.robots': (t, d) => [
    ...(d.sitemaps || []).map(u => ent('url', u)),
    ...(d.disallow || []).slice(0, 100).map(p => ent('url', `https://${t}${p}`)),
  ],
  'http.graphql': (t, d) => (d.endpoints || []).map(e => ent('url', typeof e === 'string' ? e : e.url || e)),
  'shodan.host': (t, d) => [
    ...(d.ports || []).map(p => ent('port', `${p}/tcp`, { number: p, proto: 'tcp', host: t })),
    ...(d.hostnames || []).map(h => ent('subdomain', String(h).toLowerCase())),
    ...(d.vulns || []).map(c => ent('cve', String(c).toUpperCase())),
  ],
  'censys.host': (t, d) => (d.services || []).map(s => ent('port', `${s.port}/${(s.transport || 'tcp')}`, { number: s.port, proto: s.transport || 'tcp', host: t, service: s.service_name })),
  'vuln.cve_lookup': (t, d) => (d.results || []).map(r => ent('cve', (r.id || r.cve || '').toUpperCase(), { cvss: r.cvss?.score ?? r.score, severity: r.severity })),
  'vuln.epss': (t, d) => (d.results || []).map(r => ent('cve', String(r.cve).toUpperCase(), { epss: r.epss, percentile: r.percentile, scored: true })),
};

/** Parse "PORT/tcp open service" lines out of nmap stdout. */
function parsePorts(raw, host) {
  if (!raw || typeof raw !== 'string') return [];
  const out = [];
  const re = /^(\d+)\/(tcp|udp)\s+open\s+(\S+)?/gim;
  let m;
  while ((m = re.exec(raw))) {
    out.push(ent('port', `${m[1]}/${m[2]}`, { number: Number(m[1]), proto: m[2], host, service: m[3] || null }));
  }
  return out;
}

/** Pull a tech hint from a Server/X-Powered-By header. */
function httpTech(t, d) {
  const out = [];
  const h = d.headers || {};
  const server = h.server || h.Server;
  const powered = h['x-powered-by'] || h['X-Powered-By'];
  if (server) out.push(ent('tech', String(server).split(/[ /]/)[0], { evidence: server, host: t }));
  if (powered) out.push(ent('tech', String(powered).split(/[ /]/)[0], { evidence: powered, host: t }));
  if (d.url) out.push(ent('url', d.url));
  return out;
}

/**
 * Extract entities from one executor result.
 *
 * @param uses    the executor's uses key
 * @param target  the target it ran against
 * @param data    the executor's returned object
 * @returns       Entity[] — { type, value, attrs }
 */
export function extractEntities(uses, target, data) {
  if (!data || typeof data !== 'object') return [];
  let entities = [];
  try {
    const fn = EXTRACTORS[uses];
    if (fn) entities = fn(target, data) || [];
  } catch {
    entities = [];
  }

  // Generic CVE sweep over finding messages (covers nuclei.scan and friends).
  try {
    for (const f of data.findings || []) {
      for (const cve of String(f.message || '').match(CVE_RE) || []) {
        entities.push(ent('cve', cve.toUpperCase(), { fromFinding: true }));
      }
    }
  } catch { /* ignore */ }

  // Normalise + drop empties + tag provenance.
  return entities
    .filter(e => e && e.value && e.value !== 'undefined')
    .map(e => ({ ...e, value: e.value.trim(), source: uses }));
}

/** Stable key for deduping an entity. */
export function entityKey(e) {
  return `${e.type}:${e.value.toLowerCase()}`;
}

export { IPV4_RE };
