import axios from 'axios';
import { validateTarget } from '#sdk';

/**
 * Derive candidate bucket names from a target domain.
 * e.g. "shop.example.com" → ["shop.example.com", "shop-example-com",
 *      "example", "shop", "shop-example", "exampleshop", ...]
 */
function candidateNames(domain, extra = []) {
  const labels = domain.split('.');
  const base = labels.length > 1 ? labels.slice(0, -1).join('.') : domain; // strip TLD
  const flat = base.replace(/\./g, '-');
  const firstLabel = labels[0];
  const names = new Set([
    domain,
    domain.replace(/\./g, '-'),
    base,
    flat,
    firstLabel,
    `${flat}-assets`, `${flat}-static`, `${flat}-backup`, `${flat}-backups`,
    `${flat}-media`, `${flat}-uploads`, `${flat}-data`, `${flat}-prod`, `${flat}-dev`,
    ...extra,
  ]);
  // Bucket names: lowercase, no leading/trailing dashes, 3-63 chars.
  return Array.from(names)
    .map(n => n.toLowerCase().replace(/[^a-z0-9.-]/g, '').replace(/^-+|-+$/g, ''))
    .filter(n => n.length >= 3 && n.length <= 63);
}

/**
 * Build the provider-specific URLs to probe for one candidate name.
 */
function providerUrls(name) {
  return [
    { provider: 'aws-s3',  url: `https://${name}.s3.amazonaws.com/` },
    { provider: 'aws-s3',  url: `https://s3.amazonaws.com/${name}/` },
    { provider: 'gcp-gcs', url: `https://storage.googleapis.com/${name}/` },
    { provider: 'azure',   url: `https://${name}.blob.core.windows.net/?comp=list` },
  ];
}

/**
 * Classify a probe response into a bucket state.
 */
function classify(status, body) {
  if (status === 200) {
    if (/<ListBucketResult|<EnumerationResults|<Contents>|"items"/.test(body || '')) {
      return { exists: true, access: 'public-listable', severity: 'high' };
    }
    return { exists: true, access: 'public', severity: 'medium' };
  }
  if (status === 403) return { exists: true, access: 'private', severity: 'info' };
  if (status === 401) return { exists: true, access: 'auth-required', severity: 'info' };
  // 404 / NoSuchBucket → does not exist
  return { exists: false, access: 'not-found', severity: 'none' };
}

/**
 * Cloud storage bucket finder. Derives candidate bucket names from the target
 * domain and probes AWS S3, GCP Cloud Storage, and Azure Blob endpoints for
 * public exposure. Read-only HEAD/GET probes; no credentials, no API key.
 */
export async function bucketFinder(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  // Per-probe timeout, independent of the runner's step-level budget — this
  // executor fires many probes across providers.
  const reqTimeoutMs = opts.requestTimeoutMs || 6000;
  const concurrency = Math.min(opts.concurrency || 12, 32);

  const names = candidateNames(cleanTarget, opts.extraNames || []);
  const probes = names.flatMap(name => providerUrls(name).map(p => ({ name, ...p })));

  const findings = [];
  async function probeOne(p) {
    try {
      const res = await axios.get(p.url, {
        timeout: reqTimeoutMs,
        validateStatus: () => true,
        maxRedirects: 2,
        maxContentLength: 2_000_000,
        maxBodyLength: 2_000_000,
      });
      const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data || '');
      const state = classify(res.status, body);
      if (state.exists) {
        findings.push({ name: p.name, provider: p.provider, url: p.url, status: res.status, ...state });
      }
    } catch {
      // network error / DNS miss → treat as non-existent
    }
  }

  for (let i = 0; i < probes.length; i += concurrency) {
    await Promise.all(probes.slice(i, i + concurrency).map(probeOne));
  }

  findings.sort((a, b) => {
    const order = { high: 0, medium: 1, info: 2, none: 3 };
    return order[a.severity] - order[b.severity];
  });

  return {
    target: cleanTarget,
    candidatesTried: names.length,
    probesRun: probes.length,
    found: findings.length,
    exposed: findings.filter(f => f.access === 'public' || f.access === 'public-listable'),
    findings,
  };
}
