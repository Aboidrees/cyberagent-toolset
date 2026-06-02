import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { validateTarget, validateNmapFlags, normalizeSeverity, severityRank } from '#sdk';

/**
 * Extension loader.
 *
 * Discovers extension descriptors (local `extensions/<dir>/index.js` and
 * npm-installed `cyberagent-ext-*` / `@cyberagent/ext-*` packages), validates
 * them, and builds the catalog the engine runs on: a `uses` → run registry, a
 * flat executor-metadata list, report owners, and phase/domain views.
 *
 * The catalog is memoized — `loadCatalog()` builds it once per process.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..', '..');
const EXT_DIR = path.join(ROOT, 'extensions');

// Shared services injected into every executor's run(target, opts, ctx).
const CTX = Object.freeze({ validateTarget, validateNmapFlags, normalizeSeverity, severityRank });

let _catalog = null;

async function importDescriptor(specifier, source) {
  const mod = await import(specifier);
  const d = mod.default || mod.descriptor;
  if (!d || !d.name || !Array.isArray(d.executors)) {
    throw new Error(`invalid descriptor (${source}): needs { name, executors[] }`);
  }
  d.__source = source;
  return d;
}

async function loadLocal() {
  let entries;
  try {
    entries = await fs.readdir(EXT_DIR, { withFileTypes: true });
  } catch {
    return [];
  }
  const out = [];
  for (const e of entries) {
    if (!e.isDirectory() || e.name.startsWith('_') || e.name.startsWith('.')) continue;
    const index = path.join(EXT_DIR, e.name, 'index.js');
    try {
      await fs.access(index);
      out.push(await importDescriptor(pathToFileURL(index).href, `local:${e.name}`));
    } catch (err) {
      process.stderr.write(`[extensions] skipped local "${e.name}": ${err.message}\n`);
    }
  }
  return out;
}

async function loadNpm() {
  let pkg;
  try {
    pkg = JSON.parse(await fs.readFile(path.join(ROOT, 'package.json'), 'utf8'));
  } catch {
    return [];
  }
  const names = Object.keys({
    ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies,
  });
  // Convention: cyberagent-ext-<x>, @scope/cyberagent-ext-<x>, or @cyberagent/ext-<x>.
  const matches = names.filter(n =>
    /(^|\/)cyberagent-ext-/.test(n) || /^@cyberagent\/ext-/.test(n));
  const out = [];
  for (const name of matches) {
    try {
      out.push(await importDescriptor(name, `npm:${name}`));
    } catch (err) {
      process.stderr.write(`[extensions] skipped npm "${name}": ${err.message}\n`);
    }
  }
  return out;
}

/**
 * Build (and memoize) the catalog from all discovered extensions.
 */
export async function loadCatalog({ reload = false } = {}) {
  if (_catalog && !reload) return _catalog;

  const descriptors = [...(await loadLocal()), ...(await loadNpm())];

  const registry = {};          // uses -> (target, opts) => data
  const executors = [];         // flat metadata
  const reportersByUses = {};   // uses -> owning extension's report module
  const byPhase = {};
  const byDomain = {};

  for (const d of descriptors) {
    for (const e of d.executors || []) {
      if (!e.uses || typeof e.run !== 'function') {
        process.stderr.write(`[extensions] ${d.name}: executor missing uses/run — skipped\n`);
        continue;
      }
      if (registry[e.uses]) {
        process.stderr.write(`[extensions] duplicate uses "${e.uses}" from ${d.name} — keeping first\n`);
        continue;
      }
      const meta = {
        uses: e.uses,
        extension: d.name,
        domain: e.domain || d.domain || d.name,
        phase: e.phase || 'reconnaissance',
        posture: e.posture || 'active',
        targetTypes: e.targetTypes || [],
        summary: e.summary || '',
        inputSchema: e.inputSchema || null,
        permissions: d.permissions || {},
      };
      // Bind the injected ctx so callers keep the simple (target, opts) signature.
      registry[e.uses] = (target, opts) => e.run(target, opts || {}, CTX);
      executors.push(meta);
      if (d.report) reportersByUses[e.uses] = d.report;
      (byPhase[meta.phase] ||= []).push(meta);
      (byDomain[meta.domain] ||= []).push(meta);
    }
  }

  executors.sort((a, b) => a.uses.localeCompare(b.uses));
  _catalog = { registry, executors, reportersByUses, byPhase, byDomain, descriptors };
  return _catalog;
}
