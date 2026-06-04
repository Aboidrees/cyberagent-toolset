import fs from 'fs/promises';
import os from 'os';
import path from 'path';

// Ensure a directory exists, creating it recursively if necessary
export async function ensureDir(p) {
  await fs.mkdir(p, { recursive: true });
}

/**
 * Default directory for run/assessment reports.
 *
 * Honors CATS_RUNS_DIR if set; otherwise a per-user dir (~/.cyberagent/runs) so
 * a globally-installed MCP server never writes inside its own package directory
 * (which may be read-only and is hard to find). The CLI can still override this
 * per-invocation with --out.
 */
export function defaultRunsDir() {
  return process.env.CATS_RUNS_DIR
    ? path.resolve(process.env.CATS_RUNS_DIR)
    : path.join(os.homedir(), '.cyberagent', 'runs');
}

// Generate a filename prefix with ISO timestamp (replacing disallowed characters)
export function timestampFile(prefix) {
  const t = new Date().toISOString().replace(/[:.]/g, '-');
  return `${prefix}_${t}`;
}