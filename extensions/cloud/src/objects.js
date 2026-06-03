import axios from 'axios';
import { validateTarget } from '#sdk';

/**
 * List the contents of a publicly-listable cloud bucket and flag sensitive
 * objects. This is the natural follow-up to `cloud.bucket_finder`: once a bucket
 * is found public-listable, enumerate the keys to gauge real exposure (backups,
 * dumps, secrets). Read-only: it only performs the provider's public list
 * operation (no downloads, no writes). Keyless.
 *
 * Accepts either a full bucket base `url`, or a `bucket` name + `provider`
 * (aws-s3 | gcp-gcs | azure, with an Azure `container`).
 */

const SENSITIVE = /(\.(sql|bak|backup|env|pem|ppk|key|p12|pfx|tar|t?gz|zip|7z|dump|log|ya?ml|ini|conf|config|bson)$)|(backup|dump|secret|credential|password|private|\.git\/|id_rsa)/i;

function listUrl({ url, bucket, provider, container }) {
  if (url) {
    const u = new URL(url);
    if (/s3[.-]/.test(u.host) || u.host.endsWith('amazonaws.com')) return { kind: 'xml-key', url: `${u.origin}${u.pathname.replace(/\/$/, '')}/?list-type=2` };
    if (u.host.endsWith('storage.googleapis.com')) return { kind: 'xml-key', url: `${u.origin}${u.pathname.replace(/\/$/, '')}/` };
    if (u.host.endsWith('blob.core.windows.net')) return { kind: 'xml-name', url: `${u.origin}${u.pathname.replace(/\/$/, '')}?restype=container&comp=list` };
    return { kind: 'xml-key', url: url.endsWith('/') ? url : `${url}/` };
  }
  switch (provider) {
    case 'aws-s3': return { kind: 'xml-key', url: `https://${bucket}.s3.amazonaws.com/?list-type=2` };
    case 'gcp-gcs': return { kind: 'xml-key', url: `https://storage.googleapis.com/${bucket}/` };
    case 'azure': return { kind: 'xml-name', url: `https://${bucket}.blob.core.windows.net/${container || '$root'}?restype=container&comp=list` };
    default: return null;
  }
}

function parseListing(kind, body) {
  const objects = [];
  if (kind === 'xml-name') {
    // Azure: <Blob><Name>..</Name><Properties><Content-Length>..</Content-Length>
    const blobRe = /<Blob>([\s\S]*?)<\/Blob>/g;
    let m;
    while ((m = blobRe.exec(body)) && objects.length < 1000) {
      const name = (/<Name>([\s\S]*?)<\/Name>/.exec(m[1]) || [])[1];
      const size = (/<Content-Length>(\d+)<\/Content-Length>/.exec(m[1]) || [])[1];
      if (name) objects.push({ key: name, size: size ? Number(size) : null });
    }
  } else {
    // S3 / GCS: <Contents><Key>..</Key><Size>..</Size><LastModified>..</LastModified>
    const conRe = /<Contents>([\s\S]*?)<\/Contents>/g;
    let m;
    while ((m = conRe.exec(body)) && objects.length < 1000) {
      const key = (/<Key>([\s\S]*?)<\/Key>/.exec(m[1]) || [])[1];
      const size = (/<Size>(\d+)<\/Size>/.exec(m[1]) || [])[1];
      const modified = (/<LastModified>([\s\S]*?)<\/LastModified>/.exec(m[1]) || [])[1];
      if (key) objects.push({ key, size: size ? Number(size) : null, lastModified: modified || null });
    }
  }
  return objects;
}

export async function bucketObjects(target, opts = {}) {
  // target may be a domain (informational) or unused when url/bucket given.
  let label = target;
  try { label = validateTarget(target); } catch { /* url/bucket mode */ }

  const spec = listUrl({ url: opts.url, bucket: opts.bucket, provider: opts.provider, container: opts.container });
  if (!spec) {
    return { error: 'Provide either opts.url, or opts.bucket + opts.provider (aws-s3|gcp-gcs|azure).', objects: [], findings: [] };
  }
  const limit = Math.min(opts.limit || 200, 1000);

  let res;
  try {
    res = await axios.get(spec.url, {
      timeout: opts.timeoutMs || 15000,
      validateStatus: () => true,
      maxRedirects: 3,
      maxContentLength: 20_000_000,
      responseType: 'text',
    });
  } catch (e) {
    return { target: label, url: spec.url, error: e.message, objects: [], findings: [] };
  }

  if (res.status === 403 || res.status === 401) {
    return { target: label, url: spec.url, status: res.status, listable: false, note: 'Bucket exists but listing is not public', objects: [], findings: [] };
  }
  if (res.status !== 200 || typeof res.data !== 'string') {
    return { target: label, url: spec.url, status: res.status, listable: false, objects: [], findings: [] };
  }

  const all = parseListing(spec.kind, res.data);
  const truncated = /<IsTruncated>true<\/IsTruncated>/.test(res.data) || /<NextMarker>/.test(res.data) || all.length >= 1000;
  const objects = all.slice(0, limit);
  const sensitive = all.filter(o => SENSITIVE.test(o.key)).slice(0, 50);

  const findings = [];
  if (all.length > 0) {
    findings.push({ severity: 'high', message: `Public bucket listing exposed — ${all.length}${truncated ? '+' : ''} objects readable` });
  }
  for (const s of sensitive) {
    findings.push({ severity: 'critical', message: `Sensitive object publicly listed: ${s.key}` });
  }

  return {
    target: label, url: spec.url, status: res.status,
    listable: all.length > 0,
    objectCount: all.length,
    truncated,
    sensitiveCount: sensitive.length,
    objects,
    sensitive,
    findings,
  };
}
