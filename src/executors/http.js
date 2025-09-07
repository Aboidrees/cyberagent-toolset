import axios from 'axios';

// Build a URL from scheme, host, and path
function buildUrl(scheme, host, path = '/') {
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return `${scheme || 'https'}://${host}${normalized}`;
}

// Retrieve HTTP headers for a given path.
export async function getHeaders(target, opts = {}) {
  const url = buildUrl(opts.scheme || 'https', target, opts.path || '/');
  const res = await axios.get(url, {
    timeout: opts.timeoutMs || 10000,
    validateStatus: () => true
  });
  return { url, status: res.status, headers: res.headers };
}

// Perform a GET request and return status, headers, and a snippet of the body.
export async function getPath(target, opts = {}) {
  const url = buildUrl(opts.scheme || 'https', target, opts.path || '/');
  const res = await axios.get(url, {
    timeout: opts.timeoutMs || 10000,
    validateStatus: () => true
  });
  const snippet = typeof res.data === 'string' ? res.data.slice(0, 5000) : res.data;
  return { url, status: res.status, headers: res.headers, bodySnippet: snippet };
}