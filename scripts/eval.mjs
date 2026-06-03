#!/usr/bin/env node
/**
 * Assessment eval harness — a deterministic regression for the agent layer.
 *
 * The product claim is "an agent can drive a full assessment." This exercises the
 * orchestration engine end-to-end without an LLM: it drives the pivot loop
 * programmatically (always take the top suggestions) against a golden target and
 * asserts the investigation actually progresses — entities get discovered, the
 * pivot engine surfaces new actions from them, and a report synthesizes.
 *
 * It does NOT test LLM tool-choice (that needs a live agent); it guards the
 * machinery the agent depends on. Network-dependent, so it's a separate `npm run
 * eval` rather than part of the CI validate gate.
 *
 * Usage: node scripts/eval.mjs [target]   (default: example.com, passive-only)
 */

import { loadCatalog } from '../src/extensions/loader.js';
import { createAssessment, runStep, preflightTarget } from '../src/assessment.js';
import { suggest } from '../src/pivots.js';
import { synthesize } from '../src/assessment-report.js';

const TARGET = process.argv[2] || 'example.com';
const ROUNDS = 3;
const TOP = 6;

const checks = [];
const check = (name, pass, detail = '') => {
  checks.push({ name, pass, detail });
  console.log(`${pass ? '✓' : '✗'} ${name}${detail ? ` — ${detail}` : ''}`);
};

console.log(`\nAssessment eval — target: ${TARGET} (passive)\n`);

const catalog = await loadCatalog();
const session = createAssessment({ target: TARGET, posture: 'passive' });

// 0. Preflight — a nonexistent/non-resolving target has nothing to discover, so
//    skip (not fail): a dead target must be distinguishable from a broken engine.
const reach = await preflightTarget(session);
if (!reach.resolves) {
  console.log(`⚠ SKIP — "${TARGET}" does not resolve (${reach.reason}). It may be a typo or nonexistent; there is nothing to assess.\n`);
  process.exit(0);
}
console.log(`(target resolves: ${reach.addresses.slice(0, 3).join(', ')})\n`);

// 1. Start yields a non-empty, ranked plan.
let next = suggest(session, catalog, { posture: 'passive', limit: TOP });
check('start proposes actions', next.length > 0, `${next.length} suggestions`);
check('suggestions are ranked', next.every((s, i) => i === 0 || next[i - 1].priority >= s.priority), 'priority descending');

// 2. Drive the loop: run the top suggestions, let pivots surface, repeat.
//    Record every distinct target the engine suggested — pivots onto discovered
//    entities show up here as targets other than the primary one.
const entityTypesSeen = new Set();
const pivotTargetsSeen = new Set();
for (let round = 0; round < ROUNDS; round++) {
  next = suggest(session, catalog, { posture: 'passive', limit: TOP });
  if (!next.length) break;
  for (const s of next) pivotTargetsSeen.add(s.target);
  for (const s of next) {
    const r = await runStep(session, s, catalog);
    for (const e of r.newEntities) entityTypesSeen.add(e.type);
  }
}

// 3. The investigation discovered entities beyond the seed.
const nonSeed = session.entities.filter(e => e.source !== 'seed');
check('entities discovered', nonSeed.length > 0, `${nonSeed.length} entities`);
check('discovered subdomains or IPs', entityTypesSeen.has('subdomain') || entityTypesSeen.has('ip'),
  [...entityTypesSeen].join(', ') || 'none');

// 4. The engine pivoted — it suggested actions against discovered entities, not
//    just the primary target.
check('pivots target discovered entities', [...pivotTargetsSeen].some(t => t !== session.target),
  `${pivotTargetsSeen.size} distinct targets driven`);

// 5. Report synthesizes cleanly.
let report;
try { report = synthesize(session).json; check('report synthesizes', true, `${report.coverage.stepsRun} steps`); }
catch (e) { check('report synthesizes', false, e.message); }
if (report) {
  check('report has coverage', report.coverage.stepsRun > 0, `${report.coverage.executorsUsed} executors`);
  check('report inventories entities', Object.keys(report.entities).length > 0, Object.keys(report.entities).join(', '));
}

const failed = checks.filter(c => !c.pass);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed.`);
if (failed.length) { console.error(`\n❌ Eval FAILED: ${failed.map(c => c.name).join('; ')}`); process.exit(1); }
console.log('\n✅ Eval passed — the assessment loop progresses end-to-end.');
