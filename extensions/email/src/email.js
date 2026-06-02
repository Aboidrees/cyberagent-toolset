import dns from 'dns/promises';
import axios from 'axios';
import { validateTarget } from '#sdk';

// DKIM selectors worth probing by default — covers the common providers.
const DEFAULT_SELECTORS = [
  'default', 'google', 'selector1', 'selector2',
  'k1', 'k2', 's1', 's2', 'mail', 'dkim', 'mandrill', 'mxvault',
];

/**
 * Fetch and concatenate all TXT records for a name.
 * Returns an array of full record strings (chunks within a record are joined).
 *
 * Each lookup is bounded by `timeoutMs`: some resolvers stall for tens of
 * seconds on ENODATA responses, which would otherwise block the whole
 * concurrent batch (and trip the runner's per-step timeout). On timeout we
 * treat the record as absent rather than hanging.
 */
async function txt(name, timeoutMs = 5000) {
  let timer;
  const lookup = dns.resolveTxt(name)
    .then(records => records.map(chunks => chunks.join('')))
    .catch(() => []);
  const timeout = new Promise(resolve => {
    timer = setTimeout(() => resolve([]), timeoutMs);
    timer.unref?.();   // don't keep the process alive just for this fallback timer
  });
  try {
    return await Promise.race([lookup, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Parse an SPF record into mechanisms and flag risky "all" qualifiers.
 */
function analyseSpf(record) {
  const terms = record.split(/\s+/).filter(Boolean);
  const includes = terms.filter(t => t.startsWith('include:')).map(t => t.slice(8));
  const allTerm = terms.find(t => /[-~?+]?all$/.test(t));

  const findings = [];
  if (allTerm === '+all') {
    findings.push({ severity: 'high', message: '+all allows any host to send — effectively no SPF protection.' });
  } else if (allTerm === '?all') {
    findings.push({ severity: 'medium', message: '?all (neutral) provides no enforcement.' });
  } else if (!allTerm) {
    findings.push({ severity: 'medium', message: 'No "all" mechanism — SPF policy is incomplete.' });
  }
  if (includes.length > 10) {
    findings.push({ severity: 'low', message: `${includes.length} include: chains — risks exceeding the 10 DNS-lookup limit.` });
  }

  return { record, all: allTerm || null, includes, findings };
}

/**
 * Parse a DMARC record into its tag/value pairs and evaluate the policy strength.
 */
function analyseDmarc(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const [k, v] = part.split('=').map(s => s && s.trim());
    if (k && v) tags[k.toLowerCase()] = v;
  }

  const policy = (tags.p || '').toLowerCase();
  const findings = [];
  if (policy === 'none' || !policy) {
    findings.push({ severity: 'medium', message: 'p=none — DMARC is monitor-only and does not block spoofed mail.' });
  }
  if (!tags.rua) {
    findings.push({ severity: 'low', message: 'No rua= aggregate report address — no visibility into failures.' });
  }
  if (tags.pct && Number(tags.pct) < 100) {
    findings.push({ severity: 'low', message: `pct=${tags.pct} — policy only applied to a subset of mail.` });
  }

  return { record, policy: policy || null, rua: tags.rua || null, ruf: tags.ruf || null, sp: tags.sp || null, pct: tags.pct || null, findings };
}

/**
 * Analyse a domain's email security posture: SPF, DMARC, DKIM, MTA-STS, BIMI.
 * Purely passive — DNS TXT lookups plus one HTTPS fetch for the MTA-STS policy.
 * Requires no API keys.
 */
export async function security(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const selectors = opts.selectors || DEFAULT_SELECTORS;
  const timeoutMs = opts.timeoutMs || 8000;
  // Bound each DNS query independently of the overall step budget so a single
  // slow resolver response can't stall the whole assessment.
  const dnsTimeoutMs = opts.dnsTimeoutMs || 6000;

  const result = { target: cleanTarget };

  // Fire every DNS lookup concurrently — these are independent records and
  // probing selectors sequentially would make the executor needlessly slow
  // (and risk tripping per-step timeouts in the runner).
  const [rootTxt, dmarcTxt, mtaStsTxt, bimiTxt, ...dkimResults] = await Promise.all([
    txt(cleanTarget, dnsTimeoutMs),
    txt(`_dmarc.${cleanTarget}`, dnsTimeoutMs),
    txt(`_mta-sts.${cleanTarget}`, dnsTimeoutMs),
    txt(`default._bimi.${cleanTarget}`, dnsTimeoutMs),
    ...selectors.map(sel => txt(`${sel}._domainkey.${cleanTarget}`, dnsTimeoutMs).then(recs => ({ sel, recs }))),
  ]);

  // ── SPF ──────────────────────────────────────────────────────────────────
  const spfRecord = rootTxt.find(r => r.toLowerCase().startsWith('v=spf1'));
  result.spf = spfRecord
    ? analyseSpf(spfRecord)
    : { record: null, present: false, findings: [{ severity: 'high', message: 'No SPF record — domain can be freely spoofed.' }] };

  // ── DMARC ────────────────────────────────────────────────────────────────
  const dmarcRecord = dmarcTxt.find(r => r.toLowerCase().startsWith('v=dmarc1'));
  result.dmarc = dmarcRecord
    ? analyseDmarc(dmarcRecord)
    : { record: null, present: false, findings: [{ severity: 'high', message: 'No DMARC record — no policy against spoofing.' }] };

  // ── DKIM ─────────────────────────────────────────────────────────────────
  const dkim = { selectorsTried: selectors, found: [] };
  for (const { sel, recs } of dkimResults) {
    const key = recs.find(r => /v=DKIM1|p=/i.test(r));
    if (key) dkim.found.push({ selector: sel, record: key });
  }
  if (dkim.found.length === 0) {
    dkim.findings = [{ severity: 'low', message: 'No DKIM key found for the probed selectors (it may use a custom selector).' }];
  }
  result.dkim = dkim;

  // ── MTA-STS ──────────────────────────────────────────────────────────────
  const mtaStsRecord = mtaStsTxt.find(r => r.toLowerCase().startsWith('v=stsv1'));
  const mtaSts = { txtRecord: mtaStsRecord || null, present: Boolean(mtaStsRecord) };
  if (mtaStsRecord) {
    try {
      const res = await axios.get(`https://mta-sts.${cleanTarget}/.well-known/mta-sts.txt`, {
        timeout: timeoutMs,
        validateStatus: () => true,
        maxRedirects: 3,
      });
      if (res.status === 200 && typeof res.data === 'string') {
        mtaSts.policy = res.data.slice(0, 2000);
        const mode = (res.data.match(/mode:\s*(\w+)/i) || [])[1];
        mtaSts.mode = mode || null;
        if (mode && mode.toLowerCase() === 'testing') {
          mtaSts.findings = [{ severity: 'low', message: 'MTA-STS mode=testing — policy is not yet enforced.' }];
        }
      }
    } catch {
      mtaSts.policyError = 'Policy file not reachable at mta-sts.<domain>/.well-known/mta-sts.txt';
    }
  } else {
    mtaSts.findings = [{ severity: 'low', message: 'No MTA-STS record — no enforced TLS for inbound mail.' }];
  }
  result.mtaSts = mtaSts;

  // ── BIMI ─────────────────────────────────────────────────────────────────
  const bimiRecord = bimiTxt.find(r => r.toLowerCase().startsWith('v=bimi1'));
  result.bimi = {
    record: bimiRecord || null,
    present: Boolean(bimiRecord),
    logo: bimiRecord ? (bimiRecord.match(/l=([^;]+)/i) || [])[1] || null : null,
  };

  // ── Roll-up of all findings ────────────────────────────────────────────────
  const allFindings = [];
  for (const section of ['spf', 'dmarc', 'dkim', 'mtaSts']) {
    for (const f of result[section]?.findings || []) {
      allFindings.push({ check: section, ...f });
    }
  }
  result.findings = allFindings;
  result.summary = {
    spf: result.spf.record ? 'present' : 'missing',
    dmarc: result.dmarc.policy || (result.dmarc.record ? 'present' : 'missing'),
    dkim: result.dkim.found.length > 0 ? `${result.dkim.found.length} selector(s)` : 'none found',
    mtaSts: result.mtaSts.present ? (result.mtaSts.mode || 'present') : 'missing',
    bimi: result.bimi.present ? 'present' : 'missing',
  };

  return result;
}
