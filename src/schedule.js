import cron from 'node-cron';
import path from 'path';
import fs from 'fs/promises';
import { runPlaybook } from './runner.js';
import { resolvePlaybook } from './utils/playbooks.js';
import { ensureDir } from './utils/fsx.js';
import { loadCatalog } from './extensions/loader.js';
import { createAssessment, runStep, saveAssessment, preflightTarget } from './assessment.js';
import { suggest } from './pivots.js';
import { synthesize, toRunReport } from './assessment-report.js';
import { notify } from './utils/notify.js';

/**
 * Scheduled scanning — run a playbook against a target on a cron schedule.
 *
 * Starts a long-running process that fires the playbook on each cron tick. New
 * findings flow through the normal report + webhook-notification path, so
 * configuring SLACK_WEBHOOK_URL / WEBHOOK_URL turns this into a monitoring loop.
 *
 * Resolves the playbook by id (from playbooks/) or by direct .yaml/.md file path.
 */
export async function scheduleScan({ playbook, target, cronExpr, outDir, stepTimeoutMs, runImmediately = false, log = console.error }) {
  if (!cron.validate(cronExpr)) {
    throw new Error(`Invalid cron expression: "${cronExpr}"`);
  }

  // Resolve the playbook by id (bundled) or by direct .yaml/.md path.
  const playbookPath = await resolvePlaybook(playbook);

  await ensureDir(outDir);

  let runCount = 0;
  const runOnce = async () => {
    runCount += 1;
    const stamp = new Date().toISOString();
    log(`[schedule] run #${runCount} starting at ${stamp} — ${playbook} → ${target}`);
    try {
      const r = await runPlaybook({ playbookPath, outDir, varOverrides: { target }, stepTimeoutMs });
      const top = r.report.topSeverity || 'none';
      log(`[schedule] run #${runCount} done — top severity: ${top}, report: ${r.jsonPath}`);
      return r;
    } catch (e) {
      log(`[schedule] run #${runCount} failed: ${e.message}`);
      return null;
    }
  };

  const task = cron.schedule(cronExpr, runOnce);
  log(`[schedule] scheduled "${playbook}" against ${target} on "${cronExpr}". Ctrl-C to stop.`);

  if (runImmediately) await runOnce();

  return { task, runOnce, get runCount() { return runCount; } };
}

/**
 * Scheduled assessment — drive a full agentic assessment against a target on a
 * cron schedule, the dynamic/pivot-driven counterpart of scheduleScan. Each tick
 * runs a fresh assessment to completion, writes a JSON + Markdown report, and
 * routes findings through the same notifier (NOTIFY_ON_SEVERITY) — turning the
 * assessment engine into a monitoring loop with full run-parity.
 */
export async function scheduleAssessment({ target, cronExpr, outDir, stepTimeoutMs, top = 5, maxRounds = 12, posture, runImmediately = false, log = console.error }) {
  if (!cron.validate(cronExpr)) {
    throw new Error(`Invalid cron expression: "${cronExpr}"`);
  }
  await ensureDir(outDir);
  const catalog = await loadCatalog();

  let runCount = 0;
  const runOnce = async () => {
    runCount += 1;
    const stamp = new Date().toISOString();
    log(`[schedule] assessment #${runCount} starting at ${stamp} — ${target}`);
    try {
      const session = createAssessment({ target, posture });
      const reach = await preflightTarget(session);
      if (reach.resolves) {
        let round = 0;
        while (round < maxRounds) {
          const batch = suggest(session, catalog, { posture, limit: top });
          if (!batch.length) break;
          round++;
          for (const s of batch) await runStep(session, s, catalog);
          await saveAssessment(session);
        }
      }
      await saveAssessment(session);

      const { json, markdown } = synthesize(session);
      const base = path.join(outDir, `assessment-${session.id}`);
      const jsonPath = `${base}.json`, mdPath = `${base}.md`;
      await fs.writeFile(jsonPath, JSON.stringify(json, null, 2));
      await fs.writeFile(mdPath, markdown);

      const report = toRunReport(session, json);
      const notification = await notify({ report, jsonPath, mdPath }).catch(e => ({ sent: false, reason: e.message }));
      log(`[schedule] assessment #${runCount} done — top severity: ${json.topSeverity || 'none'}, ${session.findings.length} findings, report: ${jsonPath}${notification?.sent ? ' (notified)' : ''}`);
      return { session, json, jsonPath, mdPath, notification };
    } catch (e) {
      log(`[schedule] assessment #${runCount} failed: ${e.message}`);
      return null;
    }
  };

  const task = cron.schedule(cronExpr, runOnce);
  log(`[schedule] scheduled assessment of ${target} on "${cronExpr}". Ctrl-C to stop.`);

  if (runImmediately) await runOnce();

  return { task, runOnce, get runCount() { return runCount; } };
}
