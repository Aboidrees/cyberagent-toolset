import dns from 'dns/promises';
import axios from 'axios';
import { validateTarget } from '#sdk';

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

/**
 * VirusTotal reputation — aggregates ~90 security vendors' verdicts for an IP or
 * domain. Surfaces how many flag the target malicious/suspicious, plus the
 * community reputation score. Key-gated (free public key); no-op without it.
 */
export async function virustotalLookup(target, opts = {}, ctx = {}) {
  const clean = validateTarget(target);
  const apiKey = opts.apiKey || (ctx.env ? ctx.env('VIRUSTOTAL_API_KEY') : process.env.VIRUSTOTAL_API_KEY);
  if (!apiKey) {
    return { target: clean, checked: false, note: 'Skipped — set VIRUSTOTAL_API_KEY (free: virustotal.com) to enable.' };
  }

  // Query the IP endpoint for IPs, the domain endpoint otherwise.
  let kind, id;
  if (IPV4.test(clean)) { kind = 'ip'; id = clean; }
  else { kind = 'domain'; id = clean; }
  const path = kind === 'ip' ? `ip_addresses/${id}` : `domains/${id}`;

  const res = await axios.get(`https://www.virustotal.com/api/v3/${path}`, {
    headers: { 'x-apikey': apiKey, accept: 'application/json' },
    timeout: opts.timeoutMs || 15000, validateStatus: () => true,
  });
  if (res.status === 401) return { target: clean, checked: false, note: 'VirusTotal rejected the API key (401).' };
  if (res.status === 429) return { target: clean, checked: false, note: 'VirusTotal rate limit reached (429).' };
  if (res.status !== 200 || !res.data?.data) return { target: clean, checked: false, note: `VirusTotal HTTP ${res.status}` };

  const attr = res.data.data.attributes || {};
  const stats = attr.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const findings = [];
  if (malicious > 0) {
    findings.push({ severity: malicious >= 5 ? 'high' : 'medium', message: `VirusTotal: ${malicious} vendor(s) flag ${clean} as malicious` });
  } else if (suspicious > 0) {
    findings.push({ severity: 'low', message: `VirusTotal: ${suspicious} vendor(s) flag ${clean} as suspicious` });
  }

  return {
    target: clean, kind, checked: true,
    malicious, suspicious, harmless: stats.harmless || 0, undetected: stats.undetected || 0,
    reputation: attr.reputation ?? null,
    asOwner: attr.as_owner || null, country: attr.country || null,
    findings,
  };
}
