import axios from 'axios';

// Query crt.sh for certificate transparency entries and extract subdomains.
async function fromCrtSh(domain) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  const res = await axios.get(url, { timeout: 15000 });
  const names = new Set();
  for (const row of res.data || []) {
    const cn = String(row?.name_value || '').split('\n');
    cn.forEach(n => {
      const cleaned = n.trim().toLowerCase();
      if (cleaned.endsWith(`.${domain}`) || cleaned === domain) {
        names.add(cleaned);
      }
    });
  }
  return Array.from(names).sort();
}

// Perform passive subdomain enumeration using various sources.
export async function passive(domain, opts = {}) {
  const sources = opts.sources || ['crtsh'];
  const out = {};
  if (sources.includes('crtsh')) {
    try {
      out.crtsh = await fromCrtSh(domain);
    } catch (e) {
      out.crtsh = { error: e.message || String(e) };
    }
  }
  // Combine all arrays of subdomains into one unique list
  const merged = Array.from(new Set([].concat(...Object.values(out).map(v => Array.isArray(v) ? v : [])))).sort();
  return { merged, sources: out };
}