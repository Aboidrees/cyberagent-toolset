import fs from 'fs/promises';
import yaml from 'js-yaml';
import { runPlaybook } from './runner.js';
import { loadPlaybooks } from './utils/playbooks.js';
import { ensureDir } from './utils/fsx.js';

/**
 * Target watchlist — run a batch of playbooks against a list of targets defined
 * in a YAML file, in one command.
 *
 * watchlist.yml:
 *   targets:
 *     - host: example.com
 *       playbooks: [quick-web-recon, web-security-recon]
 *     - host: api.example.com
 *       playbooks: [api-cloud-recon]
 *   vars:               # optional, applied to every run
 *     scheme: https
 */
export async function runWatchlist({ listPath, outDir, stepTimeoutMs, onProgress } = {}) {
  const raw = await fs.readFile(listPath, 'utf8');
  const list = yaml.load(raw) || {};
  const targets = list.targets || [];
  if (!Array.isArray(targets) || targets.length === 0) {
    throw new Error(`Watchlist "${listPath}" has no targets.`);
  }

  await ensureDir(outDir);
  const playbooks = await loadPlaybooks();
  const byId = new Map(playbooks.map(p => [p.id, p]));

  const results = [];
  for (const entry of targets) {
    const host = entry.host || entry.target;
    if (!host) {
      results.push({ host: null, error: 'watchlist entry missing "host"' });
      continue;
    }
    for (const playbookId of entry.playbooks || []) {
      const pb = byId.get(playbookId);
      if (!pb) {
        results.push({ host, playbook: playbookId, ok: false, error: 'playbook not found' });
        continue;
      }
      onProgress?.(`${host} → ${playbookId}`);
      try {
        const r = await runPlaybook({
          playbookPath: pb.file,
          outDir,
          varOverrides: { target: host, ...(list.vars || {}), ...(entry.vars || {}) },
          stepTimeoutMs,
        });
        results.push({
          host,
          playbook: playbookId,
          ok: true,
          jsonPath: r.jsonPath,
          mdPath: r.mdPath,
          topSeverity: r.report.topSeverity,
          severityCounts: r.report.severityCounts,
        });
      } catch (e) {
        results.push({ host, playbook: playbookId, ok: false, error: e.message });
      }
    }
  }

  return {
    listPath,
    runs: results.length,
    targets: targets.length,
    results,
  };
}
