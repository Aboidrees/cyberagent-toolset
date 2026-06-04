#!/usr/bin/env node
/**
 * LLM-in-the-loop eval — scores how well an *agent* drives a full assessment.
 *
 * Where `eval.mjs` checks the engine deterministically, this scores the agent
 * loop: an agent is given four tools (start / run / next / report) and must
 * conduct an assessment; a heuristic judge then scores the result on coverage,
 * pivoting, discovery, and report completeness.
 *
 * The agent is pluggable:
 *   - heuristic (default) — always runs the top suggestions until dry. The
 *     baseline every real agent should beat.
 *   - llm — drives the loop with Claude via tool-use. Requires
 *     ANTHROPIC_API_KEY and `npm i @anthropic-ai/sdk`; falls back to heuristic
 *     with a note if either is missing.
 *
 * Usage: node scripts/eval-llm.mjs [target] [--agent heuristic|llm]
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCatalog } from '../src/extensions/loader.js';
import { createAssessment, runStep, preflightTarget, loadAssessment, saveAssessment, listAssessments } from '../src/assessment.js';
import { suggest } from '../src/pivots.js';
import { synthesize } from '../src/assessment-report.js';
import { getPrompt } from '../src/mcp-prompts.js';

const pexec = promisify(execFile);

const AGENT = (process.argv.includes('--agent') ? process.argv[process.argv.indexOf('--agent') + 1] : process.env.EVAL_AGENT) || 'heuristic';
const POSTURE = 'passive';

// Require an explicit target — don't silently assess a default (that hides typos
// and runs against the wrong host). The first positional that isn't a flag or the
// value of --agent is the target.
const agentValueIdx = process.argv.indexOf('--agent') + 1;
const TARGET = process.argv.find((a, i) => i >= 2 && !a.startsWith('--') && i !== agentValueIdx);
if (!TARGET) {
  console.error('Usage: node scripts/eval-llm.mjs <target> [--agent heuristic|api|claude-code]\n' +
    '  e.g. node scripts/eval-llm.mjs example.com --agent claude-code\n\n' +
    'Provide an authorized target — there is no default. Targets with a golden\n' +
    'spec in this file (example.com, example.com) also get target-specific scoring.');
  process.exit(2);
}

const catalog = await loadCatalog();

// ── The four "tools" an agent drives, backed by the assessment modules ────────
const tools = {
  async start(target) {
    const s = createAssessment({ target, posture: POSTURE });
    await preflightTarget(s); await saveAssessment(s);
    return { assessmentId: s.id, reachability: s.reachability, suggestions: suggest(s, catalog, { posture: POSTURE, limit: 10 }) };
  },
  async next(id) {
    const s = await loadAssessment(id);
    return { suggestions: suggest(s, catalog, { posture: POSTURE, limit: 10 }) };
  },
  async run(id, top = 5) {
    const s = await loadAssessment(id);
    const toRun = suggest(s, catalog, { posture: POSTURE, limit: top });
    for (const step of toRun) await runStep(s, step, catalog);
    await saveAssessment(s);
    return { ran: toRun.length, suggestions: suggest(s, catalog, { posture: POSTURE, limit: top }) };
  },
  async report(id) {
    return synthesize(await loadAssessment(id)).json;
  },
};

// ── Agents ────────────────────────────────────────────────────────────────────
async function heuristicAgent(target) {
  const { assessmentId, reachability } = await tools.start(target);
  if (!reachability.resolves) return { assessmentId, skipped: reachability.reason };
  for (let round = 0; round < 6; round++) {
    const r = await tools.run(assessmentId, 5);
    if (!r.suggestions.length) break;
  }
  return { assessmentId };
}

// API agent — drives the loop with the Anthropic API (needs ANTHROPIC_API_KEY +
// @anthropic-ai/sdk). Billed via the Anthropic Console (separate from Claude Max).
async function apiAgent(target) {
  let Anthropic;
  try { ({ default: Anthropic } = await import('@anthropic-ai/sdk')); } catch { return null; }
  if (!process.env.ANTHROPIC_API_KEY) return null;
  const client = new Anthropic();
  const sys = 'You are a security recon agent. Conduct a passive assessment of the target using the tools. ' +
    'Start, then repeatedly run the top suggestions to pivot on discovered entities, then produce a report. Stop when suggestions run dry.';
  const toolDefs = [
    { name: 'start', description: 'Start an assessment', input_schema: { type: 'object', properties: { target: { type: 'string' } }, required: ['target'] } },
    { name: 'run', description: 'Run the top N suggestions', input_schema: { type: 'object', properties: { id: { type: 'string' }, top: { type: 'number' } }, required: ['id'] } },
    { name: 'next', description: 'List ranked next actions', input_schema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
    { name: 'report', description: 'Synthesize the report', input_schema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
  ];
  const messages = [{ role: 'user', content: `Assess "${target}". Begin.` }];
  let assessmentId = null;
  for (let turn = 0; turn < 12; turn++) {
    const resp = await client.messages.create({ model: 'claude-sonnet-4-6', max_tokens: 1024, system: sys, tools: toolDefs, messages });
    messages.push({ role: 'assistant', content: resp.content });
    const calls = resp.content.filter(c => c.type === 'tool_use');
    if (!calls.length) break;
    const results = [];
    for (const call of calls) {
      const i = call.input || {};
      let out;
      try {
        if (call.name === 'start') out = await tools.start(i.target || target);
        else if (call.name === 'run') out = await tools.run(i.id, i.top || 5);
        else if (call.name === 'next') out = await tools.next(i.id);
        else if (call.name === 'report') out = await tools.report(i.id);
        else out = { error: `unknown tool ${call.name}` };
      } catch (e) { out = { error: e.message }; }
      if (call.name === 'start' && out.assessmentId) assessmentId = out.assessmentId;
      results.push({ type: 'tool_result', tool_use_id: call.id, content: JSON.stringify(out).slice(0, 2000) });
    }
    messages.push({ role: 'user', content: results });
  }
  return { assessmentId };
}

// Claude Code agent — drives the loop through the `claude` CLI in headless mode,
// connected to the CATS MCP server. Uses your Claude Code auth (a Claude Max
// subscription via OAuth, or ANTHROPIC_API_KEY) — no separate API key required.
// The MCP server persists assessments to runs/assessments/, so we read the one
// it created back off disk and score it.
async function claudeCodeAgent(target) {
  try { await pexec('claude', ['--version'], { timeout: 10000 }); } catch { return null; } // CLI not installed

  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const mcpConfig = JSON.stringify({ mcpServers: { cats: { command: 'node', args: [path.join(root, 'src', 'mcp-server.js')] } } });
  const allow = ['cats_assess_start', 'cats_assess_run', 'cats_assess_next', 'cats_assess_report']
    .map(t => `mcp__cats__${t}`).join(',');
  const prompt = getPrompt('assess-domain', { target, passive: 'true' }).messages[0].content.text;

  const before = new Set((await listAssessments()).map(a => a.id));
  try {
    await pexec('claude', [
      '-p', prompt,
      '--output-format', 'json',
      '--mcp-config', mcpConfig,
      '--strict-mcp-config',
      '--allowedTools', allow,
    ], { timeout: 300000, maxBuffer: 32 * 1024 * 1024 });
  } catch (e) {
    // claude may exit non-zero; the assessment may still have been produced.
    if (!e.stdout) return { error: `claude CLI failed: ${e.message}` };
  }
  const created = (await listAssessments()).find(a => !before.has(a.id) && a.target === target);
  return created ? { assessmentId: created.id } : { error: 'no assessment was produced by the claude-code run' };
}

// ── Golden expectations per target ────────────────────────────────────────────
// What a *good* assessment of a known target should surface. When a target has a
// golden spec, the judge reserves a "golden" dimension that scores the run
// against these concrete expectations instead of generic heuristics alone — a
// much sharper signal than "ran N executors". Add targets you assess regularly.
const GOLDEN = {
  'example.com': {
    minExecutors: 6,
    executors: ['dns.resolve', 'rdap.lookup', 'whois.lookup', 'tls.inspect', 'http.security_score'],
    entityTypes: ['ip'],
    minFindings: 0,
  },
  'example.com': {
    minExecutors: 8,
    executors: ['dns.resolve', 'subdomains.passive', 'tls.inspect', 'http.security_score', 'email.security'],
    entityTypes: ['ip', 'subdomain'],
    minFindings: 1,
  },
};

// Score a report against its golden spec (0–20). Returns points + a human detail.
function goldenScore(report, spec) {
  const ran = new Set(report.coverage?.executors || []);
  const haveTypes = new Set(Object.keys(report.entityCounts || {}));
  const findings = (report.findings || []).length;

  const execHit = spec.executors.filter(u => ran.has(u)).length;
  const execPts = spec.executors.length ? Math.round((execHit / spec.executors.length) * 8) : 8;   // up to 8
  const typeHit = spec.entityTypes.filter(t => haveTypes.has(t)).length;
  const typePts = spec.entityTypes.length ? Math.round((typeHit / spec.entityTypes.length) * 6) : 6; // up to 6
  const minExecPts = (report.coverage?.executorsUsed || 0) >= spec.minExecutors ? 3 : 0;            // 3
  const minFindPts = findings >= spec.minFindings ? 3 : 0;                                           // 3

  const points = execPts + typePts + minExecPts + minFindPts;
  const detail = `executors ${execHit}/${spec.executors.length}, entity-types ${typeHit}/${spec.entityTypes.length}, ` +
    `≥${spec.minExecutors} execs ${minExecPts ? '✓' : '✗'}, ≥${spec.minFindings} findings ${minFindPts ? '✓' : '✗'}`;
  return { points, detail };
}

// ── Judge: score the resulting assessment (0–100) ─────────────────────────────
// With a golden spec: coverage 25 + discovery 25 + pivoting 15 + report 15 + golden 20.
// Without one: the original generic 30 + 30 + 20 + 20.
function judge(report, target) {
  const breakdown = {};
  const ents = report.entityCounts || {};
  const nonPrimaryEntities = Object.entries(ents).filter(([t]) => t !== 'domain').reduce((s, [, n]) => s + n, 0);
  const spec = GOLDEN[target];

  if (spec) {
    breakdown.coverage = Math.min(25, (report.coverage?.executorsUsed || 0) * 2.5);
    breakdown.discovery = Math.min(25, nonPrimaryEntities * 4);
    breakdown.pivoting = Math.min(15, Object.keys(ents).length * 4);
    breakdown.report = (report.coverage?.stepsRun > 0 ? 7 : 0) + (Object.keys(report.entities || {}).length > 1 ? 8 : 0);
    const g = goldenScore(report, spec);
    breakdown.golden = g.points;
    const score = Math.round(Object.values(breakdown).reduce((a, b) => a + b, 0));
    return { score, breakdown, goldenDetail: g.detail };
  }

  breakdown.coverage = Math.min(30, (report.coverage?.executorsUsed || 0) * 3);              // up to 30
  breakdown.discovery = Math.min(30, nonPrimaryEntities * 5);                                 // up to 30
  breakdown.pivoting = Math.min(20, Object.keys(ents).length * 5);                            // up to 20 (entity-type diversity)
  breakdown.report = (report.coverage?.stepsRun > 0 ? 10 : 0) + (Object.keys(report.entities || {}).length > 1 ? 10 : 0); // up to 20
  const score = Object.values(breakdown).reduce((a, b) => a + b, 0);
  return { score, breakdown };
}

// ── Run ────────────────────────────────────────────────────────────────────────
console.log(`\nLLM-in-the-loop eval — target: ${TARGET}, agent: ${AGENT}\n`);

const UNAVAILABLE = {
  api: 'needs ANTHROPIC_API_KEY + `npm i @anthropic-ai/sdk` (Anthropic Console billing)',
  'claude-code': 'needs the `claude` CLI on PATH (Claude Code / Max subscription)',
};
const AGENTS = { heuristic: heuristicAgent, api: apiAgent, llm: apiAgent, 'claude-code': claudeCodeAgent };

const driver = AGENTS[AGENT];
if (!driver) { console.error(`Unknown agent "${AGENT}". Use: heuristic | api | claude-code`); process.exit(2); }

let usedAgent = AGENT === 'llm' ? 'api' : AGENT;
let outcome = await driver(TARGET).catch(e => ({ error: e.message }));

// Graceful fallback to the heuristic baseline when a real agent isn't available.
if (!outcome || outcome.error || outcome === null) {
  if (AGENT !== 'heuristic') {
    const why = outcome?.error || UNAVAILABLE[usedAgent] || 'unavailable';
    console.log(`ℹ ${usedAgent} agent unavailable (${why}) — using heuristic baseline.\n`);
    usedAgent = 'heuristic (fallback)';
    outcome = await heuristicAgent(TARGET);
  }
}

if (outcome.skipped) { console.log(`SKIP — target unresolvable (${outcome.skipped}).`); process.exit(0); }
const report = await tools.report(outcome.assessmentId);
const { score, breakdown, goldenDetail } = judge(report, TARGET);
printScore(usedAgent, score, breakdown, report, goldenDetail);
process.exit(score >= 50 ? 0 : 1);

function printScore(agent, score, breakdown, report, goldenDetail) {
  console.log(`Agent: ${agent}`);
  console.log(`Coverage:  ${report.coverage.executorsUsed} executors, ${report.coverage.stepsRun} steps`);
  console.log(`Entities:  ${Object.entries(report.entityCounts || {}).map(([t, n]) => `${t}:${n}`).join(' ') || 'none'}`);
  console.log(`Findings:  ${(report.findings || []).length}`);
  if (goldenDetail) console.log(`Golden:    ${goldenDetail}`);
  console.log('\nScore breakdown:');
  for (const [k, v] of Object.entries(breakdown)) console.log(`  ${k.padEnd(10)} ${v}`);
  console.log(`\n${score >= 50 ? '✅' : '❌'} Total: ${score}/100  (pass ≥ 50)`);
}
