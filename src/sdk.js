/**
 * Extension SDK — the stable surface that extensions build against.
 *
 * Local extensions import this via the package `imports` map: `import { ... }
 * from '#sdk'`. The same services are also injected into each executor's
 * `run(target, opts, ctx)` as `ctx`, so npm-installed plugins (which can't reach
 * our internal modules) can use `ctx.validateTarget` instead.
 *
 * Keep this surface small and stable — it is the contract third-party extensions
 * depend on.
 */

export { validateTarget, validateNmapFlags } from './utils/validate.js';

/** OS detection + command-availability helpers (for exec-based executors). */
export { getOSInfo, isCommandAvailable } from './utils/os.js';

/** Severity ordering helpers shared by report modules. */
export { normalizeSeverity, severityRank } from './utils/findings.js';
