import axios from 'axios';
import { validateTarget } from '../utils/validate.js';

/**
 * Build a URL from scheme, host, and path.
 * Path is normalised to always start with '/'.
 */
function buildUrl(scheme, host, urlPath = '/') {
  const normalised = urlPath.startsWith('/') ? urlPath : `/${urlPath}`;
  return `${scheme || 'https'}://${host}${normalised}`;
}

/**
 * Retrieve HTTP response headers for a given path.
 * Returns { url, status, headers }.
 */
export async function getHeaders(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', cleanTarget, opts.path || '/');

  const res = await axios.get(url, {
    timeout: opts.timeoutMs || 10000,
    validateStatus: () => true,   // never throw on HTTP error codes
    maxRedirects: 5,
  });

  return { url, status: res.status, headers: res.headers };
}

/**
 * Perform a GET request and return status, headers, and a body snippet.
 * Body is truncated to 5000 chars to avoid overwhelming the caller.
 */
export async function getPath(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', cleanTarget, opts.path || '/');

  const res = await axios.get(url, {
    timeout: opts.timeoutMs || 10000,
    validateStatus: () => true,
    maxRedirects: 5,
  });

  const snippet =
    typeof res.data === 'string' ? res.data.slice(0, 5000) : res.data;

  return { url, status: res.status, headers: res.headers, bodySnippet: snippet };
}
