import dns from 'dns/promises';
import axios from 'axios';
import { validateTarget } from '#sdk';

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
async function toIp(target) {
  if (IPV4.test(target)) return target;
  const a = await dns.resolve4(target);
  if (!a.length) throw new Error(`could not resolve ${target}`);
  return a[0];
}

/**
 * GreyNoise — is an IP "internet background noise" (mass scanners/bots) or
 * targeted? The Community API classifies an IP (benign / malicious / unknown) and
 * flags RIOT (known-good business services). Useful to triage whether a source IP
 * in your logs is worth chasing. Key-gated (free community key); no-op without it.
 */
export async function greynoiseIp(target, opts = {}, ctx = {}) {
  const clean = validateTarget(target);
  const apiKey = opts.apiKey || (ctx.env ? ctx.env('GREYNOISE_API_KEY') : process.env.GREYNOISE_API_KEY);
  if (!apiKey) {
    return { target: clean, checked: false, note: 'Skipped — set GREYNOISE_API_KEY (free community key: greynoise.io) to enable.' };
  }
  let ip;
  try { ip = await toIp(clean); } catch (e) { return { target: clean, checked: false, note: e.message }; }

  const res = await axios.get(`https://api.greynoise.io/v3/community/${ip}`, {
    headers: { key: apiKey, accept: 'application/json' },
    timeout: opts.timeoutMs || 12000, validateStatus: () => true,
  });
  if (res.status === 404) return { target: clean, ip, checked: true, seen: false, note: 'IP not observed by GreyNoise' };
  if (res.status === 401) return { target: clean, ip, checked: false, note: 'GreyNoise rejected the API key (401).' };
  if (res.status !== 200 || !res.data) return { target: clean, ip, checked: false, note: `GreyNoise HTTP ${res.status}` };

  const d = res.data;
  const findings = [];
  if (d.classification === 'malicious') findings.push({ severity: 'high', message: `GreyNoise classifies ${ip} as malicious${d.name ? ` (${d.name})` : ''}` });
  else if (d.noise) findings.push({ severity: 'info', message: `${ip} is internet background noise${d.name ? ` (${d.name})` : ''}` });
  if (d.riot) findings.push({ severity: 'info', message: `${ip} is a known business service (RIOT)${d.name ? `: ${d.name}` : ''}` });

  return {
    target: clean, ip, checked: true, seen: true,
    noise: Boolean(d.noise), riot: Boolean(d.riot),
    classification: d.classification || null, name: d.name || null, lastSeen: d.last_seen || null,
    findings,
  };
}
