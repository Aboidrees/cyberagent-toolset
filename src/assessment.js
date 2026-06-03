/**
 * Assessment sessions — the stateful core of agent-driven recon.
 *
 * An assessment is a long-running investigation against one target. Instead of
 * firing one-shot executor calls, the agent (or CLI) grows a session: each
 * executor result is folded in — findings deduped, entities extracted into a
 * graph — and the pivot engine (`src/pivots.js`) proposes the next best actions
 * from what's been discovered. The session persists to `runs/assessments/<id>.json`
 * so it survives across CLI invocations and MCP restarts.
 */

import path from 'path';
import { randomUUID } from 'crypto';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';
import { ensureDir } from './utils/fsx.js';
import { extractFindings, severityRank } from './utils/findings.js';
import { extractEntities, entityKey } from './entities.js';
import { inferTargetType, targetHost } from './auto.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.join(__dirname, '..', 'runs', 'assessments');

const nowISO = () => new Date().toISOString();
const stepKey = (uses, target) => `${uses}@${target}`;

/** Create a new assessment session (not yet persisted). */
export function createAssessment({ target, posture } = {}) {
  if (!target) throw new Error('createAssessment requires a target');
  const type = inferTargetType(target);
  const host = targetHost(target, type);
  const session = {
    id: `a-${randomUUID().slice(0, 8)}`,
    target: host,
    rawTarget: target,
    targetType: type,
    posture: posture || null,
    status: 'active',
    createdAt: nowISO(),
    updatedAt: nowISO(),
    steps: [],          // { uses, target, at, ok, error, findingCount, entityCount }
    findings: [],       // deduped { severity, message, uses, target }
    entities: [],       // deduped { type, value, attrs, source, firstSeen, scanned }
  };
  // Seed the entity graph with the target itself.
  session.entities.push({
    type: type === 'ip' ? 'ip' : type === 'url' ? 'url' : 'domain',
    value: host, attrs: { seed: true }, source: 'seed', firstSeen: nowISO(), scanned: false,
  });
  return session;
}

const findingKey = (f) => `${f.severity}|${f.uses}|${f.message}`;

/** Fold one executor result into the session: findings + entities, deduped. */
function ingest(session, { uses, target, ok, error, data }) {
  let newFindings = [];
  let newEntities = [];

  if (ok && data) {
    // Findings via the same path the runner uses (generic + extension reporters).
    const reporters = session._reporters || {};
    const flist = extractFindings({ outputs: [{ name: uses, uses, ok: true, data }] }, reporters);
    const seenF = new Set(session.findings.map(findingKey));
    for (const f of flist) {
      const rec = { severity: f.severity, message: f.message, uses, target };
      if (!seenF.has(findingKey(rec))) { seenF.add(findingKey(rec)); session.findings.push(rec); newFindings.push(rec); }
    }

    // Entities.
    const index = new Map(session.entities.map(e => [entityKey(e), e]));
    for (const e of extractEntities(uses, target, data)) {
      const k = entityKey(e);
      const existing = index.get(k);
      if (existing) {
        existing.attrs = { ...existing.attrs, ...e.attrs };
      } else {
        const rec = { type: e.type, value: e.value, attrs: e.attrs, source: e.source, firstSeen: nowISO(), scanned: false };
        session.entities.push(rec); index.set(k, rec); newEntities.push(rec);
      }
    }
  }

  // Mark the entity we just scanned (so pivots don't re-suggest it).
  const scannedEnt = session.entities.find(e => e.value.toLowerCase() === String(target).toLowerCase());
  if (scannedEnt) scannedEnt.scanned = true;

  session.steps.push({
    uses, target, at: nowISO(), ok: Boolean(ok), error: error || null,
    findingCount: newFindings.length, entityCount: newEntities.length,
  });
  session.findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  session.updatedAt = nowISO();
  return { newFindings, newEntities };
}

/** Has this (uses, target) already been run in this session? */
export function hasRun(session, uses, target) {
  return session.steps.some(s => stepKey(s.uses, s.target) === stepKey(uses, target));
}

/**
 * Run one executor against a target and fold the result into the session.
 * Returns { step, data, newFindings, newEntities }.
 */
export async function runStep(session, { uses, target, opts = {} }, catalog) {
  const run = catalog.registry[uses];
  if (!run) throw new Error(`Unknown executor "${uses}"`);
  const tgt = target || session.target;
  session._reporters = catalog.reportersByUses;

  let data, ok = true, error = null;
  try {
    data = await run(tgt, opts);
  } catch (e) {
    ok = false; error = e.message; data = null;
  }
  const { newFindings, newEntities } = ingest(session, { uses, target: tgt, ok, error, data });
  return { uses, target: tgt, ok, error, data, newFindings, newEntities };
}

// ── persistence ──────────────────────────────────────────────────────────────
function serialisable(session) {
  const { _reporters, ...rest } = session;   // never persist the live catalog
  return rest;
}

export async function saveAssessment(session) {
  await ensureDir(DIR);
  await fs.writeFile(path.join(DIR, `${session.id}.json`), JSON.stringify(serialisable(session), null, 2));
  return session.id;
}

export async function loadAssessment(id) {
  try {
    const raw = await fs.readFile(path.join(DIR, `${id}.json`), 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function listAssessments() {
  try {
    const files = await fs.readdir(DIR);
    const out = [];
    for (const f of files.filter(n => n.endsWith('.json'))) {
      try {
        const s = JSON.parse(await fs.readFile(path.join(DIR, f), 'utf8'));
        out.push({ id: s.id, target: s.target, status: s.status, steps: s.steps.length, findings: s.findings.length, updatedAt: s.updatedAt });
      } catch { /* skip corrupt */ }
    }
    return out.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
  } catch {
    return [];
  }
}
