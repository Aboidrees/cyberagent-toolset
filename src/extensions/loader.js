import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { validateTarget, validateNmapFlags, normalizeSeverity, severityRank, isCommandAvailable } from '#sdk';

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

// Stable shared services every executor's ctx is built from.
const BASE_CTX = { validateTarget, validateNmapFlags, normalizeSeverity, severityRank };

let _catalog = null;

/**
 * Normalize an extension's declared permissions to { network[], env[], bins[] }.
 * Warns (once) on a malformed manifest so authors notice, without failing load.
 */
function normalizePermissions(descriptor) {
  const p = descriptor.permissions || {};
  const arr = (v, field) => {
    if (v === undefined) return [];
    if (Array.isArray(v) && v.every(x => typeof x === 'string')) return v;
    process.stderr.write(`[permissions] ${descriptor.name}: permissions.${field} must be a string[] — ignoring\n`);
    return [];
  };
  return { network: arr(p.network, 'network'), env: arr(p.env, 'env'), bins: arr(p.bins, 'bins') };
}

/**
 * Build the permission-scoped ctx injected into an extension's executors.
 * `ctx.env(key)` and `ctx.requireBin(name)` enforce the extension's declared
 * `permissions`: in strict mode an undeclared access throws; otherwise it warns
 * (once per key) but still proceeds, so existing extensions keep working.
 */
function makeCtx(descriptor, permissions, strict) {
  const declaredEnv = new Set(permissions.env);
  const declaredBins = new Set(permissions.bins);
  const warned = new Set();
  const warnOrThrow = (kind, name) => {
    const msg = `[permissions] ${descriptor.name}: undeclared ${kind} "${name}" (add it to permissions.${kind === 'env' ? 'env' : 'bins'})`;
    if (strict) throw new Error(msg);
    if (!warned.has(`${kind}:${name}`)) { warned.add(`${kind}:${name}`); process.stderr.write(msg + '\n'); }
  };
  return Object.freeze({
    ...BASE_CTX,
    permissions,
    env(key) {
      if (!declaredEnv.has(key)) warnOrThrow('env', key);
      return process.env[key];
    },
    async requireBin(name) {
      if (!declaredBins.has(name)) warnOrThrow('bins', name);
      return isCommandAvailable(name);
    },
  });
}

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
export async function loadCatalog({ reload = false, strictPermissions } = {}) {
  if (_catalog && !reload) return _catalog;

  const strict = strictPermissions ?? (process.env.CATS_STRICT_PERMISSIONS === '1');
  const descriptors = [...(await loadLocal()), ...(await loadNpm())];

  const registry = {};          // uses -> (target, opts) => data
  const executors = [];         // flat metadata
  const reportersByUses = {};   // uses -> owning extension's report module
  const byPhase = {};
  const byDomain = {};

  for (const d of descriptors) {
    // One permission-scoped ctx per extension, reused across its executors.
    const permissions = normalizePermissions(d);
    d.permissions = permissions;
    const ctx = makeCtx(d, permissions, strict);
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
        permissions,
      };
      // Bind the per-extension scoped ctx so callers keep the (target, opts) signature.
      registry[e.uses] = (target, opts) => e.run(target, opts || {}, ctx);
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
