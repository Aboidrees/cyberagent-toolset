#!/usr/bin/env node
/**
 * CyberAgentToolSet (CATS) — Model Context Protocol server  v0.12.0
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
} from '@modelcontextprotocol/sdk/types.js';
import path from 'path';
import { fileURLToPath } from 'url';

import { loadCatalog }   from './extensions/loader.js';
import { runPlaybook }   from './runner.js';
import { ensureDir }     from './utils/fsx.js';
import { loadPlaybooks } from './utils/playbooks.js';

const VERSION = '0.12.0';
const PREFIX  = 'cats';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RUNS_DIR  = path.join(__dirname, '..', 'runs');

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

  const ALL_TOOLS = [
    ...buildExecutorTools(catalog),
    ...buildOrchestrationTools(PLAYBOOKS),
    ...buildPlaybookTools(PLAYBOOKS),
  ];

  const server = new Server(
    { name: 'cyberagent-toolset', version: VERSION },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: ALL_TOOLS }));

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

      } else if (name.startsWith(`${PREFIX}_play__`)) {
        const suffix = name.slice(`${PREFIX}_play__`.length);
        const pb = PLAYBOOKS.find(p => p.toolName === suffix);
        if (!pb) throw new Error(`No playbook matched tool "${name}".`);
        await ensureDir(RUNS_DIR);
        result = await runPlaybook({
          playbookPath: pb.file, outDir: RUNS_DIR,
          varOverrides: { target: args.target, ...(args.vars || {}) }, stepTimeoutMs: args.stepTimeoutMs, posture: args.passive ? "passive" : undefined,
        });

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
    `CyberAgentToolSet (CATS) v${VERSION} ready — ${ALL_TOOLS.length} tools ` +
    `(${catalog.executors.length} executors + ${PLAYBOOKS.length} playbooks + 4 orchestration)\n`
  );
}

main().catch(err => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});
