import axios from 'axios';
import { validateTarget } from '#sdk';

/**
 * RDAP (RFC 9083) is the structured, JSON-over-HTTPS successor to WHOIS. Unlike
 * scraping free-text WHOIS, it returns machine-readable registration data with
 * consistent fields and no per-registrar rate-limit games. Keyless — we use the
 * rdap.org redirector, which forwards to the authoritative RDAP server for the
 * domain's TLD or the IP's RIR.
 */

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6_RE = /^[0-9a-fA-F:]{2,39}$/;

/** Pull `fn` (name) and `email` out of a jCard (vcardArray). */
function parseVcard(vcardArray) {
  const out = {};
  if (!Array.isArray(vcardArray) || vcardArray[1] === undefined) return out;
  for (const entry of vcardArray[1]) {
    if (!Array.isArray(entry)) continue;
    const [prop, , , value] = entry;
    if (prop === 'fn' && value) out.name = value;
    if (prop === 'email' && value) out.email = value;
    if (prop === 'org' && value) out.org = Array.isArray(value) ? value.join(' ') : value;
  }
  return out;
}

/** Flatten RDAP entities into { role: {name,email,org} } across nested entities. */
function collectEntities(entities, acc = {}) {
  for (const e of entities || []) {
    const card = parseVcard(e.vcardArray);
    for (const role of e.roles || []) {
      if (!acc[role]) acc[role] = card;
    }
    if (e.entities) collectEntities(e.entities, acc);
  }
  return acc;
}

function eventsToObject(events) {
  const out = {};
  for (const ev of events || []) {
    if (ev.eventAction && ev.eventDate) out[ev.eventAction] = ev.eventDate;
  }
  return out;
}

export async function rdapLookup(target, opts = {}) {
  const clean = validateTarget(target);
  const isIp = IPV4_RE.test(clean) || (IPV6_RE.test(clean) && clean.includes(':'));
  const kind = isIp ? 'ip' : 'domain';
  const url = `https://rdap.org/${kind}/${encodeURIComponent(clean)}`;

  let res;
  try {
    res = await axios.get(url, {
      timeout: opts.timeoutMs || 15000,
      validateStatus: () => true,
      maxRedirects: 5,
      maxContentLength: 3_000_000,
      headers: { accept: 'application/rdap+json' },
    });
  } catch (e) {
    return { target: clean, kind, error: `RDAP request failed: ${e.message}` };
  }

  if (res.status === 404) {
    return { target: clean, kind, found: false, note: 'No RDAP record (unregistered or TLD without RDAP)' };
  }
  if (res.status !== 200 || !res.data || typeof res.data !== 'object') {
    return { target: clean, kind, error: `RDAP returned HTTP ${res.status}` };
  }

  const d = res.data;
  const entities = collectEntities(d.entities);
  const events = eventsToObject(d.events);
  const findings = [];

  if (kind === 'domain') {
    const expiry = events.expiration ? Date.parse(events.expiration) : NaN;
    const serverDate = Date.parse(res.headers?.date || '');
    if (!Number.isNaN(expiry) && !Number.isNaN(serverDate)) {
      const daysLeft = Math.round((expiry - serverDate) / 86_400_000);
      if (daysLeft <= 30) {
        findings.push({
          severity: daysLeft <= 0 ? 'high' : 'low',
          message: daysLeft <= 0
            ? `Domain expired (${events.expiration})`
            : `Domain expires in ${daysLeft} days (${events.expiration})`,
        });
      }
    }
    return {
      target: clean, kind, found: true,
      handle: d.handle || d.ldhName,
      name: d.ldhName || d.unicodeName,
      status: d.status || [],
      registrar: entities.registrar?.name || entities.registrar?.org || null,
      abuseContact: entities.abuse?.email || null,
      registrant: entities.registrant?.name || entities.registrant?.org || null,
      events,
      nameservers: (d.nameservers || []).map(n => (n.ldhName || '').toLowerCase()).filter(Boolean),
      dnssec: d.secureDNS ? Boolean(d.secureDNS.delegationSigned) : null,
      findings,
    };
  }

  // IP / network object
  return {
    target: clean, kind, found: true,
    handle: d.handle,
    name: d.name,
    type: d.type,
    country: d.country || null,
    startAddress: d.startAddress,
    endAddress: d.endAddress,
    cidr: Array.isArray(d.cidr0_cidrs)
      ? d.cidr0_cidrs.map(c => `${c.v4prefix || c.v6prefix}/${c.length}`)
      : undefined,
    abuseContact: entities.abuse?.email || null,
    registrant: entities.registrant?.name || entities.registrant?.org || null,
    events,
    findings,
  };
}
