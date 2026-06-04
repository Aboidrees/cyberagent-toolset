#!/usr/bin/env node
/**
 * CyberAgentToolSet (CATS) — Model Context Protocol server
 *
 * Tools are generated dynamically from two sources:
 *   1. The extension catalog — one `cats_<uses>` tool per executor, discovered
 *      from local extensions/ and npm cyberagent-ext-* plugins.
 *   2. The playbooks/ directory — one `cats_play__<id>` tool per playbook, plus
 *      orchestration tools (cats_topics, cats_run, cats_run_multi).
 *
 * Nothing is hardcoded — drop in an extension or a playbook and restart.
 *
 * Transport: stdio. Claude Desktop config:
 *   { "mcpServers": { "cyberagent": {
 *       "command": "node",
 *       "args": ["/abs/path/to/src/mcp-server.js"] } } }
 */

import './env.js';
import { Server }               from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ReadResourceRequestSchema,
  SubscribeRequestSchema,
  UnsubscribeRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';

import { loadCatalog }   from './extensions/loader.js';
import { runPlaybook }   from './runner.js';
import { ensureDir, defaultRunsDir } from './utils/fsx.js';
import { loadPlaybooks } from './utils/playbooks.js';
import {
  createAssessment, runStep, saveAssessment, loadAssessment, preflightTarget,
} from './assessment.js';
import { suggest }       from './pivots.js';
import { synthesize }    from './assessment-report.js';
import { listResources, listResourceTemplates, readResource } from './mcp-resources.js';
import { PROMPTS, getPrompt } from './mcp-prompts.js';

const PREFIX  = 'cats';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Single source of truth — read from package.json so the banner never drifts.
const VERSION = JSON.parse(readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')).version;
const RUNS_DIR  = defaultRunsDir();

const usesToTool = (uses) => `${PREFIX}_${uses.replace(/[^a-zA-Z0-9]/g, '_')}`;

// ─────────────────────────────────────────────────────────────────────────────
// Executor tools — one per catalog executor
// ─────────────────────────────────────────────────────────────────────────────
function buildExecutorTools(catalog) {
  return catalog.executors.map(e => {
    const props = { ...(e.inputSchema || { target: { type: 'string', description: 'Target' } }) };
    const required = props.target ? ['target'] : [];
    return {
      name: usesToTool(e.uses),
      description: `[${e.phase} · ${e.posture} · ${e.domain}] ${e.summary} (uses: ${e.uses})`,
      inputSchema: { type: 'object', properties: props, required },
    };
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration + per-playbook tools
// ─────────────────────────────────────────────────────────────────────────────
function buildOrchestrationTools(playbooks) {
  const choices = playbooks.map(p => `"${p.id}"`).join(', ');
  return [
    {
      name: `${PREFIX}_capabilities`,
      description:
        'List every executor grouped by phase (reconnaissance/scanning/gaining-access), ' +
        'posture (passive/active), and domain. Use to discover what the toolset can do.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: `${PREFIX}_topics`,
      description:
        'List every available playbook with id, title, description, step count, and executors. ' +
        'Call this FIRST to present options before running.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: `${PREFIX}_run`,
      description: `Run a single playbook against a target. Available ids: ${choices}.`,
      inputSchema: {
        type: 'object',
        properties: {
          target:        { type: 'string', description: 'Target hostname or IP' },
          playbook:      { type: 'string', description: 'Playbook id' },
          vars:          { type: 'object', description: 'Extra variables (optional)' },
          stepTimeoutMs: { type: 'number', description: 'Per-step timeout override (optional)' },
          passive:       { type: "boolean", description: "Passive-only: skip active executors (optional)" },
        },
        required: ['target', 'playbook'],
      },
    },
    {
      name: `${PREFIX}_run_multi`,
      description: `Run MULTIPLE playbooks against one target. Available ids: ${choices}.`,
      inputSchema: {
        type: 'object',
        properties: {
          target:        { type: 'string', description: 'Target hostname or IP' },
          playbooks:     { type: 'array', items: { type: 'string' }, description: 'Playbook ids' },
          vars:          { type: 'object', description: 'Variables injected into every playbook (optional)' },
          stepTimeoutMs: { type: 'number', description: 'Per-step timeout override (optional)' },
          passive:       { type: "boolean", description: "Passive-only: skip active executors (optional)" },
        },
        required: ['target', 'playbooks'],
      },
    },
    {
      name: `${PREFIX}_assess_start`,
      description:
        'Start a STATEFUL recon assessment of a target. Returns an assessmentId and a ranked ' +
        'list of next-best executors to run. This is the preferred way to drive a full assessment: ' +
        'start → run → (entities discovered → new suggestions) → report. Use over one-off executor calls.',
      inputSchema: {
        type: 'object',
        properties: {
          target:  { type: 'string', description: 'Domain, IP, or URL to assess' },
          passive: { type: 'boolean', description: 'Passive-only (OSINT, no packets to the host)' },
        },
        required: ['target'],
      },
    },
    {
      name: `${PREFIX}_assess_next`,
      description: 'List the ranked next-best actions for an assessment (the pivot engine) without running them.',
      inputSchema: {
        type: 'object',
        properties: {
          assessmentId: { type: 'string', description: 'Assessment id from cats_assess_start' },
          passive:      { type: 'boolean', description: 'Restrict suggestions to passive executors' },
          limit:        { type: 'number', description: 'Max suggestions. Default: 10' },
        },
        required: ['assessmentId'],
      },
    },
    {
      name: `${PREFIX}_assess_run`,
      description:
        'Run executors inside an assessment and fold the results in (findings deduped, entities ' +
        'extracted, new pivots surfaced). Either run the top-N suggestions (default), or a specific ' +
        'executor via `uses` (+ optional `on` target). Returns what was discovered + updated suggestions.',
      inputSchema: {
        type: 'object',
        properties: {
          assessmentId: { type: 'string', description: 'Assessment id' },
          top:          { type: 'number', description: 'Run the top-N suggested actions. Default: 3' },
          uses:         { type: 'string', description: 'Run a specific executor instead (e.g. "smb.probe")' },
          on:           { type: 'string', description: 'Target for `uses` (defaults to the assessment target)' },
          opts:         { type: 'object', description: 'Options for `uses` (the executor\'s `with` block)' },
          passive:      { type: 'boolean', description: 'Restrict to passive executors' },
        },
        required: ['assessmentId'],
      },
    },
    {
      name: `${PREFIX}_assess_report`,
      description: 'Synthesize an assessment into a prioritized report — correlated findings (CVE×EPSS), entity inventory, coverage.',
      inputSchema: {
        type: 'object',
        properties: {
          assessmentId: { type: 'string', description: 'Assessment id' },
          format:       { type: 'string', description: '"json" (default) or "markdown"' },
        },
        required: ['assessmentId'],
      },
    },
    {
      name: `${PREFIX}_execute`,
      description:
        'Run any single executor by its `uses` key (e.g. "dns.resolve", "smb.probe"). Discover the ' +
        'available keys via cats_capabilities. This one tool covers all executors — useful in lean ' +
        'tool mode where the per-executor tools are not exposed.',
      inputSchema: {
        type: 'object',
        properties: {
          uses:   { type: 'string', description: 'Executor uses key (from cats_capabilities)' },
          target: { type: 'string', description: 'Target host/domain/ip/url' },
          opts:   { type: 'object', description: 'Executor options (its `with` block)' },
        },
        required: ['uses', 'target'],
      },
    },
  ];
}

function buildPlaybookTools(playbooks) {
  return playbooks.map(pb => ({
    name: `${PREFIX}_play__${pb.toolName}`,
    description: `[${pb.title}] ${pb.description} Steps (${pb.stepCount}): ${pb.steps.join(' → ')}.`,
    inputSchema: {
      type: 'object',
      properties: {
        target:  { type: 'string', description: 'Target hostname or IP address' },
        vars:    { type: 'object', description: 'Override playbook variables (optional)' },
        passive: { type: 'boolean', description: 'Passive-only: skip active executors (optional)' },
      },
      required: ['target'],
    },
  }));
}

// ─────────────────────────────────────────────────────────────────────────────
async function main() {
  const catalog   = await loadCatalog();
  const PLAYBOOKS = await loadPlaybooks();

  process.stderr.write(
    `Loaded ${catalog.descriptors.length} extensions (${catalog.executors.length} executors), ` +
    `${PLAYBOOKS.length} playbooks\n`
  );

  // Reverse map: tool name -> uses key, for dispatch.
  const toolToUses = new Map(catalog.executors.map(e => [usesToTool(e.uses), e.uses]));

  // Tool surface: "full" exposes one tool per executor (default); "lean" hides the
  // 56 granular executor tools so agent tool-choice stays sharp — executors are
  // still reachable via cats_execute + discoverable via cats_capabilities.
  const lean = (process.env.CATS_TOOL_MODE || 'full').toLowerCase() === 'lean';
  const ALL_TOOLS = [
    ...(lean ? [] : buildExecutorTools(catalog)),
    ...buildOrchestrationTools(PLAYBOOKS),
    ...buildPlaybookTools(PLAYBOOKS),
  ];

  const server = new Server(
    { name: 'cyberagent-toolset', version: VERSION },
    { capabilities: { tools: {}, resources: { subscribe: true }, prompts: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: ALL_TOOLS }));

  // ── Resources: capabilities + saved assessments (readable state) ────────────
  server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: await listResources(catalog) }));
  server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({ resourceTemplates: listResourceTemplates() }));
  server.setRequestHandler(ReadResourceRequestSchema, async (req) => readResource(req.params.uri, { catalog }));

  // ── Resource subscriptions: push updates as an assessment progresses ────────
  const subscriptions = new Set();
  server.setRequestHandler(SubscribeRequestSchema, async (req) => { subscriptions.add(req.params.uri); return {}; });
  server.setRequestHandler(UnsubscribeRequestSchema, async (req) => { subscriptions.delete(req.params.uri); return {}; });
  const notifyUpdated = (uri) => {
    if (subscriptions.has(uri)) server.notification({ method: 'notifications/resources/updated', params: { uri } }).catch(() => {});
  };
  // Notify every resource view affected by an assessment change.
  const notifyAssessment = (id) => {
    notifyUpdated('cats://assessments');
    notifyUpdated(`cats://assessment/${id}`);
    notifyUpdated(`cats://assessment/${id}/report`);
  };

  // ── Prompts: one-click agent workflows ──────────────────────────────────────
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: PROMPTS }));
  server.setRequestHandler(GetPromptRequestSchema, async (req) => getPrompt(req.params.name, req.params.arguments || {}));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    try {
      let result;

      if (name === `${PREFIX}_capabilities`) {
        result = {
          phases: Object.fromEntries(Object.entries(catalog.byPhase).map(([p, list]) =>
            [p, list.map(e => ({ uses: e.uses, posture: e.posture, domain: e.domain, summary: e.summary }))])),
          domains: Object.keys(catalog.byDomain).sort(),
          extensions: catalog.descriptors.map(d => ({ name: d.name, version: d.version, description: d.description })),
        };

      } else if (name === `${PREFIX}_topics`) {
        result = PLAYBOOKS.map(pb => ({
          id: pb.id, title: pb.title, description: pb.description,
          stepCount: pb.stepCount, steps: pb.steps, executors: pb.executors, defaultVars: pb.defaultVars,
        }));

      } else if (name === `${PREFIX}_run`) {
        const pb = PLAYBOOKS.find(p => p.id === args.playbook);
        if (!pb) throw new Error(`Playbook "${args.playbook}" not found. Available: ${PLAYBOOKS.map(p => p.id).join(', ')}`);
        await ensureDir(RUNS_DIR);
        result = await runPlaybook({
          playbookPath: pb.file, outDir: RUNS_DIR,
          varOverrides: { target: args.target, ...(args.vars || {}) }, stepTimeoutMs: args.stepTimeoutMs, posture: args.passive ? "passive" : undefined,
        });

      } else if (name === `${PREFIX}_run_multi`) {
        await ensureDir(RUNS_DIR);
        const results = [];
        for (const id of (args.playbooks || [])) {
          const pb = PLAYBOOKS.find(p => p.id === id);
          if (!pb) { results.push({ playbook: id, ok: false, error: 'not found' }); continue; }
          try {
            const r = await runPlaybook({
              playbookPath: pb.file, outDir: RUNS_DIR,
              varOverrides: { target: args.target, ...(args.vars || {}) }, stepTimeoutMs: args.stepTimeoutMs, posture: args.passive ? "passive" : undefined,
            });
            results.push({ playbook: id, title: pb.title, ok: true, jsonPath: r.jsonPath, mdPath: r.mdPath, report: r.report });
          } catch (e) {
            results.push({ playbook: id, title: pb.title, ok: false, error: e.message });
          }
        }
        result = { target: args.target, playbooksRun: results.length, results };

      } else if (name === `${PREFIX}_assess_start`) {
        const posture = args.passive ? 'passive' : undefined;
        const session = createAssessment({ target: args.target, posture });
        const reachability = await preflightTarget(session);
        await saveAssessment(session);
        notifyAssessment(session.id);
        result = {
          assessmentId: session.id, target: session.target, targetType: session.targetType,
          reachability,
          ...(reachability.resolves ? {} : { warning: `Target does not resolve (${reachability.reason}) — likely a typo or nonexistent. Verify the hostname before assessing.` }),
          suggestions: suggest(session, catalog, { posture, limit: args.limit || 10 }),
          hint: 'Run actions with cats_assess_run, then cats_assess_report when done.',
        };

      } else if (name === `${PREFIX}_assess_next`) {
        const session = await loadAssessment(args.assessmentId);
        if (!session) throw new Error(`Assessment "${args.assessmentId}" not found.`);
        result = { assessmentId: session.id, suggestions: suggest(session, catalog, { posture: args.passive ? 'passive' : undefined, limit: args.limit || 10 }) };

      } else if (name === `${PREFIX}_assess_run`) {
        const session = await loadAssessment(args.assessmentId);
        if (!session) throw new Error(`Assessment "${args.assessmentId}" not found.`);
        const posture = args.passive ? 'passive' : undefined;
        const toRun = args.uses
          ? [{ uses: args.uses, target: args.on || session.target, opts: args.opts || {} }]
          : suggest(session, catalog, { posture, limit: args.top || 3 });
        const ran = [];
        for (const s of toRun) {
          const r = await runStep(session, s, catalog);
          ran.push({ uses: r.uses, target: r.target, ok: r.ok, error: r.error, newFindings: r.newFindings, newEntities: r.newEntities.map(e => ({ type: e.type, value: e.value })) });
        }
        await saveAssessment(session);
        notifyAssessment(session.id);
        result = {
          assessmentId: session.id, ran,
          totals: { steps: session.steps.length, findings: session.findings.length, entities: session.entities.length },
          suggestions: suggest(session, catalog, { posture, limit: args.top || 3 }),
        };

      } else if (name === `${PREFIX}_assess_report`) {
        const session = await loadAssessment(args.assessmentId);
        if (!session) throw new Error(`Assessment "${args.assessmentId}" not found.`);
        const { json, markdown } = synthesize(session);
        result = args.format === 'markdown' ? { markdown } : json;

      } else if (name.startsWith(`${PREFIX}_play__`)) {
        const suffix = name.slice(`${PREFIX}_play__`.length);
        const pb = PLAYBOOKS.find(p => p.toolName === suffix);
        if (!pb) throw new Error(`No playbook matched tool "${name}".`);
        await ensureDir(RUNS_DIR);
        result = await runPlaybook({
          playbookPath: pb.file, outDir: RUNS_DIR,
          varOverrides: { target: args.target, ...(args.vars || {}) }, stepTimeoutMs: args.stepTimeoutMs, posture: args.passive ? "passive" : undefined,
        });

      } else if (name === `${PREFIX}_execute`) {
        // Generic executor runner — run any `uses` key (the lean-mode entry point).
        const run = catalog.registry[args.uses];
        if (!run) throw new Error(`Unknown executor "${args.uses}". See cats_capabilities for valid keys.`);
        result = await run(args.target, { target: args.target, ...(args.opts || {}) });

      } else if (toolToUses.has(name)) {
        // Executor tool — dispatch generically through the catalog registry.
        const uses = toolToUses.get(name);
        result = await catalog.registry[uses](args.target, args);

      } else {
        throw new Error(`Unknown tool: "${name}"`);
      }

      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(
    `CyberAgentToolSet (CATS) v${VERSION} ready — ${ALL_TOOLS.length} tools` +
    `${lean ? ' (lean mode)' : ` (${catalog.executors.length} executors + ${PLAYBOOKS.length} playbooks + ${ALL_TOOLS.length - catalog.executors.length - PLAYBOOKS.length} orchestration)`}` +
    `, ${PROMPTS.length} prompts, resources on\n`
  );
}

main().catch(err => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});
