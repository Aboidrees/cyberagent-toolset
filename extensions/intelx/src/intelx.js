import axios from 'axios';
import { validateTarget } from '#sdk';

const BASE = 'https://2.intelx.io';
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * Intelligence X — searches its index of leaks, pastes, darknet and other OSINT
 * sources for a selector (domain, email, etc.) and returns the matching records'
 * metadata. Useful to gauge a target's exposure in breach/leak corpora. Two-step
 * async API (search → poll results). Key-gated (free key); no-op without it.
 */
export async function intelxSearch(target, opts = {}, ctx = {}) {
  const term = opts.term || validateTarget(target);
  const apiKey = opts.apiKey || (ctx.env ? ctx.env('INTELX_API_KEY') : process.env.INTELX_API_KEY);
  if (!apiKey) {
    return { target: term, checked: false, note: 'Skipped — set INTELX_API_KEY (free key: intelx.io) to enable.' };
  }
  const headers = { 'x-key': apiKey, 'content-type': 'application/json', accept: 'application/json' };
  const limit = Math.min(opts.limit || 50, 200);

  // 1) start the search
  let id;
  try {
    const start = await axios.post(`${BASE}/intelligent/search`,
      { term, maxresults: limit, media: 0, sort: 2, terminate: [], timeout: 0 },
      { headers, timeout: opts.timeoutMs || 15000, validateStatus: () => true });
    if (start.status === 401) return { target: term, checked: false, note: 'IntelX rejected the API key (401).' };
    if (start.status !== 200 || start.data?.id == null) return { target: term, checked: false, note: `IntelX search HTTP ${start.status}` };
    id = start.data.id;
  } catch (e) {
    return { target: term, checked: false, note: `IntelX request failed: ${e.message}` };
  }

  // 2) poll for results (status: 0 = have results, 1 = no more, 2 = expired, 3 = none)
  const records = [];
  for (let i = 0; i < 4; i++) {
    const r = await axios.get(`${BASE}/intelligent/search/result`,
      { params: { id, limit }, headers, timeout: opts.timeoutMs || 15000, validateStatus: () => true });
    if (r.status !== 200 || !r.data) break;
    for (const rec of r.data.records || []) records.push({ name: rec.name, date: rec.date, bucket: rec.bucket, media: rec.media, size: rec.size });
    if (r.data.status === 1 || r.data.status === 2 || records.length >= limit) break;
    await sleep(1200);
  }

  const buckets = [...new Set(records.map(r => r.bucket).filter(Boolean))];
  const findings = records.length
    ? [{ severity: records.length >= 20 ? 'medium' : 'low', message: `IntelX: ${records.length} record(s) reference "${term}"${buckets.length ? ` across ${buckets.length} source(s)` : ''}` }]
    : [];

  return { target: term, checked: true, total: records.length, buckets, records: records.slice(0, limit), findings };
}
