import { intelxSearch } from './src/intelx.js';

/** Intelligence X — leak/OSINT corpus search (key-gated). */
export default {
  name: 'intelx',
  version: '1.0.0',
  domain: 'intelx',
  description: 'Intelligence X — search leak/paste/darknet/OSINT sources for a selector (domain/email) and return matching records. Key-gated (INTELX_API_KEY).',
  permissions: { network: ['https'], env: ['INTELX_API_KEY'], bins: [] },
  executors: [
    {
      uses: 'intelx.search', phase: 'reconnaissance', posture: 'passive', targetTypes: ['domain'],
      summary: 'Intelligence X search — records referencing a domain/selector in leak/OSINT corpora. Requires INTELX_API_KEY.',
      run: intelxSearch,
      inputSchema: { target: { type: 'string', description: 'Domain (or selector)' }, term: { type: 'string', description: 'Override search term (email, etc.)' }, apiKey: { type: 'string', description: 'IntelX key (or INTELX_API_KEY)' } },
    },
  ],
};
