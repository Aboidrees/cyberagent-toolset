import { example } from './src/example.js';

/**
 * Extension descriptor (the "manifest"). CATS reads the default export to
 * register your executors. Discovery is automatic for npm packages named
 * `cyberagent-ext-*` / `@cyberagent/ext-*`, or drop this folder under the host's
 * `extensions/` directory.
 */
export default {
  name: 'starter',                 // unique extension name
  version: '0.1.0',
  domain: 'example',               // capability area (groups executors)
  description: 'Starter example extension — fetches a target page and returns its title.',

  // Declare everything you touch. With CATS_STRICT_PERMISSIONS=1 the engine
  // throws on any undeclared ctx.env(KEY) / ctx.requireBin(name) access.
  permissions: {
    network: ['https', 'http'],    // protocols you egress over
    env: ['EXAMPLE_API_KEY'],      // env vars you read via ctx.env(...)
    bins: [],                      // external binaries you shell out to
  },

  executors: [
    {
      uses: 'example.title',                 // stable id playbooks reference
      phase: 'reconnaissance',               // reconnaissance | scanning | gaining-access
      posture: 'active',                     // passive (no packets to host) | active
      targetTypes: ['domain', 'url', 'ip'],  // inputs this accepts
      summary: 'Fetch a page and return its <title> (template example).',
      run: example,
      inputSchema: {
        target: { type: 'string', description: 'Hostname, domain, or IP' },
        scheme: { type: 'string', description: '"http" or "https". Default: "https"' },
        apiKey: { type: 'string', description: 'Optional API key (or set EXAMPLE_API_KEY)' },
        timeoutMs: { type: 'number', description: 'Request timeout ms. Default: 10000' },
      },
    },
  ],
};
