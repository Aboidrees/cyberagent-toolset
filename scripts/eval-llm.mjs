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

import { loadCatalog } from '../src/extensions/loader.js';
import { createAssessment, runStep, preflightTarget, loadAssessment, saveAssessment } from '../src/assessment.js';
import { suggest } from '../src/pivots.js';
import { synthesize } from '../src/assessment-report.js';

const TARGET = process.argv.find((a, i) => i >= 2 && !a.startsWith('--')) || 'example.com';
const AGENT = (process.argv.includes('--agent') ? process.argv[process.argv.indexOf('--agent') + 1] : process.env.EVAL_AGENT) || 'heuristic';
const POSTURE = 'passive';

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

async function llmAgent(target) {
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

// ── Judge: score the resulting assessment (0–100) ─────────────────────────────
function judge(report) {
  const breakdown = {};
  const ents = report.entityCounts || {};
  const nonPrimaryEntities = Object.entries(ents).filter(([t]) => t !== 'domain').reduce((s, [, n]) => s + n, 0);

  breakdown.coverage = Math.min(30, (report.coverage?.executorsUsed || 0) * 3);              // up to 30
  breakdown.discovery = Math.min(30, nonPrimaryEntities * 5);                                 // up to 30
  breakdown.pivoting = Math.min(20, Object.keys(ents).length * 5);                            // up to 20 (entity-type diversity)
  breakdown.report = (report.coverage?.stepsRun > 0 ? 10 : 0) + (Object.keys(report.entities || {}).length > 1 ? 10 : 0); // up to 20
  const score = Object.values(breakdown).reduce((a, b) => a + b, 0);
  return { score, breakdown };
}

// ── Run ────────────────────────────────────────────────────────────────────────
console.log(`\nLLM-in-the-loop eval — target: ${TARGET}, agent: ${AGENT}\n`);

let driver = heuristicAgent;
if (AGENT === 'llm') {
  const probe = await llmAgent(TARGET).catch(() => null);
  if (probe === null) {
    console.log('ℹ llm agent unavailable (needs ANTHROPIC_API_KEY + `npm i @anthropic-ai/sdk`) — using heuristic baseline.\n');
  } else {
    // already ran; judge it
    if (probe.skipped) { console.log(`SKIP — target unresolvable (${probe.skipped}).`); process.exit(0); }
    const report = await tools.report(probe.assessmentId);
    const { score, breakdown } = judge(report);
    printScore('llm', score, breakdown, report);
    process.exit(score >= 50 ? 0 : 1);
  }
}

const outcome = await driver(TARGET);
if (outcome.skipped) { console.log(`SKIP — target unresolvable (${outcome.skipped}).`); process.exit(0); }
const report = await tools.report(outcome.assessmentId);
const { score, breakdown } = judge(report);
printScore(AGENT === 'llm' ? 'heuristic (fallback)' : 'heuristic', score, breakdown, report);
process.exit(score >= 50 ? 0 : 1);

function printScore(agent, score, breakdown, report) {
  console.log(`Agent: ${agent}`);
  console.log(`Coverage:  ${report.coverage.executorsUsed} executors, ${report.coverage.stepsRun} steps`);
  console.log(`Entities:  ${Object.entries(report.entityCounts || {}).map(([t, n]) => `${t}:${n}`).join(' ') || 'none'}`);
  console.log(`Findings:  ${(report.findings || []).length}`);
  console.log('\nScore breakdown:');
  for (const [k, v] of Object.entries(breakdown)) console.log(`  ${k.padEnd(10)} ${v}`);
  console.log(`\n${score >= 50 ? '✅' : '❌'} Total: ${score}/100  (pass ≥ 50)`);
}
