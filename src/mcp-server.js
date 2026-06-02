/**
 * MCP Recon Runner — Dynamic Model Context Protocol Server  v0.4.0
 *
 * Architecture
 * ────────────
 * 1. At startup, every .md file in playbooks/ is scanned and registered as
 *    its own MCP tool (recon_play__<id>). No code changes needed to add a
 *    new playbook — just drop a file in the folder and restart the server.
 *
 * 2. recon_topics   → lists every available playbook with full metadata so
 *    the AI (or caller) can present options to the user before running.
 *
 * 3. recon_run      → runs ONE playbook by id against a target.
 *
 * 4. recon_run_multi → runs MANY playbooks in one call, aggregating results.
 *
 * 5. Low-level executor tools remain available for ad-hoc targeted queries.
 *
 * Typical interactive flow
 * ────────────────────────
 *   Claude: calls recon_topics  → gets list of playbooks with descriptions
 *   Claude: asks user to pick one or more (AskUserQuestion multi-select)
 *   User:   selects e.g. ["quick-web-recon", "web-security-recon"]
 *   Claude: calls recon_run_multi { target, playbooks: [...] }
 *   Claude: presents aggregated findings
 *
 * Transport: stdio (standard for local MCP servers)
 *
 * Claude Desktop config (~/.claude/claude_desktop_config.json):
 *   {
 *     "mcpServers": {
 *       "recon": {
 *         "command": "node",
 *         "args": ["/absolute/path/to/mcp-recon-runner/src/mcp-server.js"]
 *       }
 *     }
 *   }
 */

import { Server }               from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import fs   from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

// Executors
import { resolveDNS, reverseDNS }              from './executors/dns.js';
import { lookupWhois }                         from './executors/whois.js';
import { scanNmap }                            from './executors/nmap.js';
import { getHeaders, getPath, securityScore,
         wafDetect, fingerprint }              from './executors/http.js';
import { inspectTLS, deepTLS }                 from './executors/tls.js';
import { passive }                             from './executors/subdomains.js';
import { ping }                                from './executors/ping.js';
import { traceroute }                          from './executors/traceroute.js';
import { security as emailSecurity }           from './executors/email.js';
import { intel as ipIntel }                    from './executors/ip.js';

// Utilities
import { runPlaybook }                       from './runner.js';
import { ensureDir }                         from './utils/fsx.js';
import { loadPlaybooks, PLAYBOOKS_DIR }      from './utils/playbooks.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RUNS_DIR  = path.join(__dirname, '..', 'runs');

// ─────────────────────────────────────────────────────────────────────────────
// Static low-level executor tools (always present, target-only callers)
// ─────────────────────────────────────────────────────────────────────────────
const EXECUTOR_TOOLS = [
  {
    name: 'recon_dns',
    description:
      'Resolve DNS records for a domain. Returns A, AAAA, NS, MX, TXT, CNAME, SOA etc. ' +
      'Good for quick infrastructure mapping.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Domain to query (e.g. "example.com")' },
        types: {
          type: 'array', items: { type: 'string' },
          description: 'Record types. Default: ["A","AAAA"]. Options: A,AAAA,CNAME,NS,MX,TXT,PTR,SOA',
        },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_whois',
    description: 'WHOIS lookup — registrar, dates, name servers, registrant, abuse contact.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Domain or IP address' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_nmap',
    description:
      'nmap port scan. Non-privileged TCP connect scan by default. ' +
      'WARNING: only scan hosts you have explicit authorisation to test.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Hostname, IP, or CIDR range' },
        flags:     { type: 'string', description: 'nmap flags. Default: "-sT -Pn --top-ports 1000"' },
        timeoutMs: { type: 'number', description: 'Timeout ms. Default: 300000' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_http_headers',
    description:
      'HTTP response headers — server banner, security headers (HSTS, CSP, X-Frame-Options), cookies.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Hostname or IP' },
        path:      { type: 'string', description: 'URL path. Default: "/"' },
        scheme:    { type: 'string', description: '"http" or "https". Default: "https"' },
        timeoutMs: { type: 'number', description: 'Timeout ms. Default: 10000' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_http_get',
    description:
      'Full HTTP GET — status, headers, and body snippet (5000 chars). ' +
      'Useful for probing paths like /.env, /.git, /backup.zip.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Hostname or IP' },
        path:      { type: 'string', description: 'URL path. Default: "/"' },
        scheme:    { type: 'string', description: '"http" or "https". Default: "https"' },
        timeoutMs: { type: 'number', description: 'Timeout ms. Default: 10000' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_tls',
    description:
      'TLS/SSL inspection — certificate subject, SANs, issuer, validity dates, cipher suite. ' +
      'Flags expired certs and weak ciphers.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Hostname' },
        port:   { type: 'number', description: 'TLS port. Default: 443' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_subdomains',
    description:
      'Passive subdomain enumeration via certificate transparency logs (crt.sh). ' +
      'No active probing — safe to run first.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Base domain (e.g. "example.com")' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_ping',
    description: 'ICMP ping — reachability, packet loss, min/avg/max latency.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Hostname or IP' },
        count:     { type: 'number', description: 'Packets. Default: 4' },
        timeoutMs: { type: 'number', description: 'Timeout ms. Default: 30000' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_traceroute',
    description: 'Traceroute — hop-by-hop network path with per-hop latency.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Hostname or IP' },
        maxHops:   { type: 'number', description: 'Max hops. Default: 30' },
        timeoutMs: { type: 'number', description: 'Timeout ms. Default: 60000' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_dns_reverse',
    description:
      'Reverse DNS (PTR) lookup / sweep. Accepts a single IP, an IPv4 CIDR range ' +
      '(sweeps every host, capped at 256), or a hostname (resolves then reverses). ' +
      'Returns a per-IP PTR map plus a flat name list.',
    inputSchema: {
      type: 'object',
      properties: {
        target:   { type: 'string', description: 'IP, IPv4 CIDR (e.g. 192.168.1.0/24), or hostname' },
        maxHosts: { type: 'number', description: 'Max addresses for a CIDR sweep. Default: 256' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_email_security',
    description:
      'Email security posture — SPF, DMARC, DKIM (probes common selectors), MTA-STS, and BIMI. ' +
      'Passive DNS + one HTTPS fetch for the MTA-STS policy. Flags spoofing-enabling misconfigs.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Domain (e.g. "example.com")' },
        selectors: { type: 'array', items: { type: 'string' }, description: 'DKIM selectors to probe (optional)' },
        timeoutMs: { type: 'number', description: 'Timeout ms. Default: 8000' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_ip_intel',
    description:
      'ASN / IP intelligence via Team Cymru (keyless): ASN, BGP prefix, country, registry, ' +
      'and hosting/CDN classification. Abuse reputation is included only if ABUSEIPDB_API_KEY is set.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'IP or hostname (hostname is A-resolved)' },
        ip:     { type: 'string', description: 'Explicit IP to analyse instead of resolving target (optional)' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_http_security_score',
    description:
      'Security-header scorer — grades Content-Security-Policy, HSTS, X-Frame-Options, ' +
      'X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-* on an A–F scale ' +
      'with per-header remediation advice and info-leak detection.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Hostname or IP' },
        path:      { type: 'string', description: 'URL path. Default: "/"' },
        scheme:    { type: 'string', description: '"http" or "https". Default: "https"' },
        timeoutMs: { type: 'number', description: 'Timeout ms. Default: 10000' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_http_waf_detect',
    description:
      'WAF / CDN fingerprint from response headers, cookies, and banners. Detects Cloudflare, ' +
      'AWS WAF/CloudFront, Akamai, Imperva/Incapsula, Sucuri, F5 BIG-IP, Fastly, Varnish, Azure Front Door.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Hostname or IP' },
        path:      { type: 'string', description: 'URL path. Default: "/"' },
        scheme:    { type: 'string', description: '"http" or "https". Default: "https"' },
        timeoutMs: { type: 'number', description: 'Timeout ms. Default: 10000' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_http_fingerprint',
    description:
      'Technology stack fingerprint from headers and HTML body — server, language, framework, ' +
      'CMS, analytics, and JS libraries.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Hostname or IP' },
        path:      { type: 'string', description: 'URL path. Default: "/"' },
        scheme:    { type: 'string', description: '"http" or "https". Default: "https"' },
        deep:      { type: 'boolean', description: 'Also inspect HTML body markers. Default: true' },
        timeoutMs: { type: 'number', description: 'Timeout ms. Default: 10000' },
      },
      required: ['target'],
    },
  },
  {
    name: 'recon_tls_deep',
    description:
      'Deep TLS analysis — protocol support matrix (flags TLS 1.0/1.1), weak-cipher negotiation ' +
      '(RC4/3DES/NULL), certificate chain validation, OCSP stapling, and HSTS/preload status.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Hostname' },
        port:      { type: 'number', description: 'TLS port. Default: 443' },
        timeoutMs: { type: 'number', description: 'Per-probe timeout ms. Default: 10000' },
      },
      required: ['target'],
    },
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration tools (built once playbooks are loaded)
// ─────────────────────────────────────────────────────────────────────────────
function buildOrchestrationTools(playbooks) {
  const playbookChoices = playbooks
    .map(p => `"${p.id}" — ${p.title} (${p.stepCount} steps)`)
    .join(', ');

  return [
    // ── Topic discovery ──────────────────────────────────────────────────────
    {
      name: 'recon_topics',
      description:
        'List every available recon playbook with its full metadata: id, title, description, ' +
        'step count, step names, and executor types used. ' +
        'Call this FIRST when the user wants to start a recon session so you can present ' +
        'the options and ask which topics they want to run.',
      inputSchema: { type: 'object', properties: {} },
    },

    // ── Single playbook runner ───────────────────────────────────────────────
    {
      name: 'recon_run',
      description:
        'Run a single recon playbook against a target. ' +
        `Available playbook ids: ${playbookChoices}. ` +
        'Returns the full step-by-step results and paths to the saved JSON + Markdown report.',
      inputSchema: {
        type: 'object',
        properties: {
          target:       { type: 'string', description: 'Target hostname or IP address' },
          playbook:     { type: 'string', description: 'Playbook id (from recon_topics)' },
          vars:         { type: 'object', description: 'Extra variables to inject (optional)' },
          stepTimeoutMs:{ type: 'number', description: 'Per-step timeout override ms (optional)' },
        },
        required: ['target', 'playbook'],
      },
    },

    // ── Multi-playbook runner ────────────────────────────────────────────────
    {
      name: 'recon_run_multi',
      description:
        'Run MULTIPLE recon playbooks against a single target in one call. ' +
        'Results from each playbook are collected and returned together. ' +
        'Use this after presenting recon_topics to the user and collecting their selection. ' +
        `Available playbook ids: ${playbookChoices}.`,
      inputSchema: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target hostname or IP address' },
          playbooks: {
            type: 'array',
            items: { type: 'string' },
            description: 'Array of playbook ids to run (from recon_topics)',
          },
          vars:         { type: 'object', description: 'Variables to inject into every playbook (optional)' },
          stepTimeoutMs:{ type: 'number', description: 'Per-step timeout override ms (optional)' },
        },
        required: ['target', 'playbooks'],
      },
    },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-playbook dynamic tools  (recon_play__<id>)
// ─────────────────────────────────────────────────────────────────────────────
function buildPlaybookTools(playbooks) {
  return playbooks.map(pb => ({
    name: `recon_play__${pb.toolName}`,
    description:
      `[${pb.title}] ${pb.description} ` +
      `Steps (${pb.stepCount}): ${pb.steps.join(' → ')}. ` +
      `Executors: ${pb.executors.join(', ')}.`,
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target hostname or IP address' },
        vars:   { type: 'object', description: 'Override playbook variables (optional)' },
      },
      required: ['target'],
    },
  }));
}

// ─────────────────────────────────────────────────────────────────────────────
// Server bootstrap
// ─────────────────────────────────────────────────────────────────────────────
async function main() {
  // Load all playbooks from disk
  const PLAYBOOKS = await loadPlaybooks();
  process.stderr.write(
    `Loaded ${PLAYBOOKS.length} playbooks: ${PLAYBOOKS.map(p => p.id).join(', ')}\n`
  );

  // Build the full tool list
  const ALL_TOOLS = [
    ...EXECUTOR_TOOLS,
    ...buildOrchestrationTools(PLAYBOOKS),
    ...buildPlaybookTools(PLAYBOOKS),
  ];

  // ── MCP server ─────────────────────────────────────────────────────────────
  const server = new Server(
    { name: 'mcp-recon-runner', version: '0.4.0' },
    { capabilities: { tools: {} } }
  );

  // List tools
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: ALL_TOOLS }));

  // Call tool
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    try {
      let result;

      // ── Executor tools ──────────────────────────────────────────────────────
      switch (name) {
        case 'recon_dns':
          result = await resolveDNS(args.target, { types: args.types });
          break;

        case 'recon_whois':
          result = await lookupWhois(args.target);
          break;

        case 'recon_nmap':
          result = await scanNmap(args.target, {
            flags: args.flags,
            timeoutMs: args.timeoutMs,
          });
          break;

        case 'recon_http_headers':
          result = await getHeaders(args.target, {
            path: args.path,
            scheme: args.scheme,
            timeoutMs: args.timeoutMs,
          });
          break;

        case 'recon_http_get':
          result = await getPath(args.target, {
            path: args.path,
            scheme: args.scheme,
            timeoutMs: args.timeoutMs,
          });
          break;

        case 'recon_tls':
          result = await inspectTLS(args.target, { port: args.port });
          break;

        case 'recon_subdomains':
          result = await passive(args.target);
          break;

        case 'recon_ping':
          result = await ping(args.target, {
            count: args.count,
            timeoutMs: args.timeoutMs,
          });
          break;

        case 'recon_traceroute':
          result = await traceroute(args.target, {
            maxHops: args.maxHops,
            timeoutMs: args.timeoutMs,
          });
          break;

        case 'recon_dns_reverse':
          result = await reverseDNS(args.target, { maxHosts: args.maxHosts });
          break;

        case 'recon_email_security':
          result = await emailSecurity(args.target, {
            selectors: args.selectors,
            timeoutMs: args.timeoutMs,
          });
          break;

        case 'recon_ip_intel':
          result = await ipIntel(args.target, { ip: args.ip });
          break;

        case 'recon_http_security_score':
          result = await securityScore(args.target, {
            path: args.path,
            scheme: args.scheme,
            timeoutMs: args.timeoutMs,
          });
          break;

        case 'recon_http_waf_detect':
          result = await wafDetect(args.target, {
            path: args.path,
            scheme: args.scheme,
            timeoutMs: args.timeoutMs,
          });
          break;

        case 'recon_http_fingerprint':
          result = await fingerprint(args.target, {
            path: args.path,
            scheme: args.scheme,
            deep: args.deep,
            timeoutMs: args.timeoutMs,
          });
          break;

        case 'recon_tls_deep':
          result = await deepTLS(args.target, {
            port: args.port,
            timeoutMs: args.timeoutMs,
          });
          break;

        // ── Topic discovery ───────────────────────────────────────────────────
        case 'recon_topics':
          result = PLAYBOOKS.map(pb => ({
            id:          pb.id,
            title:       pb.title,
            description: pb.description,
            stepCount:   pb.stepCount,
            steps:       pb.steps,
            executors:   pb.executors,
            defaultVars: pb.defaultVars,
          }));
          break;

        // ── Single playbook runner ────────────────────────────────────────────
        case 'recon_run': {
          const pb = PLAYBOOKS.find(p => p.id === args.playbook);
          if (!pb) {
            throw new Error(
              `Playbook "${args.playbook}" not found. ` +
              `Available: ${PLAYBOOKS.map(p => p.id).join(', ')}`
            );
          }
          await ensureDir(RUNS_DIR);
          result = await runPlaybook({
            playbookPath:  pb.file,
            outDir:        RUNS_DIR,
            varOverrides:  { target: args.target, ...(args.vars || {}) },
            stepTimeoutMs: args.stepTimeoutMs,
          });
          break;
        }

        // ── Multi-playbook runner ─────────────────────────────────────────────
        case 'recon_run_multi': {
          await ensureDir(RUNS_DIR);
          const results = [];

          for (const playbookId of (args.playbooks || [])) {
            const pb = PLAYBOOKS.find(p => p.id === playbookId);
            if (!pb) {
              results.push({ playbook: playbookId, error: 'Playbook not found' });
              continue;
            }
            try {
              const r = await runPlaybook({
                playbookPath:  pb.file,
                outDir:        RUNS_DIR,
                varOverrides:  { target: args.target, ...(args.vars || {}) },
                stepTimeoutMs: args.stepTimeoutMs,
              });
              results.push({
                playbook: playbookId,
                title:    pb.title,
                ok:       true,
                jsonPath: r.jsonPath,
                mdPath:   r.mdPath,
                report:   r.report,
              });
            } catch (e) {
              results.push({
                playbook: playbookId,
                title:    pb.title,
                ok:       false,
                error:    e.message,
              });
            }
          }

          result = {
            target:       args.target,
            playbooksRun: results.length,
            results,
          };
          break;
        }

        // ── Dynamic per-playbook tools  (recon_play__<toolName>) ─────────────
        default: {
          if (name.startsWith('recon_play__')) {
            const toolSuffix = name.slice('recon_play__'.length);
            // Match by toolName (underscored) against loaded playbooks
            const pb = PLAYBOOKS.find(p => p.toolName === toolSuffix);
            if (!pb) {
              throw new Error(`No playbook matched tool "${name}".`);
            }
            await ensureDir(RUNS_DIR);
            result = await runPlaybook({
              playbookPath:  pb.file,
              outDir:        RUNS_DIR,
              varOverrides:  { target: args.target, ...(args.vars || {}) },
              stepTimeoutMs: args.stepTimeoutMs,
            });
          } else {
            throw new Error(`Unknown tool: "${name}"`);
          }
        }
      }

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };

    } catch (error) {
      return {
        content: [{ type: 'text', text: `Error: ${error.message}` }],
        isError: true,
      };
    }
  });

  // Start
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(
    `MCP Recon Runner v0.4.0 ready — ${ALL_TOOLS.length} tools registered ` +
    `(${EXECUTOR_TOOLS.length} executor + 3 orchestration + ${PLAYBOOKS.length} playbook)\n`
  );
}

main().catch(err => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});
