#!/usr/bin/env node
import './env.js';
import fs from 'fs/promises';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { runPlaybook } from './runner.js';
import { diffFiles, formatDiffMarkdown, hasChanges } from './diff.js';
import { runWatchlist } from './watch.js';
import { scheduleScan } from './schedule.js';
import { generateReportFromFile } from './report.js';
import { loadCatalog } from './extensions/loader.js';
import { assemble } from './auto.js';
import { ensureDir } from './utils/fsx.js';
import {
  createAssessment, runStep, saveAssessment, loadAssessment, listAssessments, preflightTarget,
} from './assessment.js';
import { suggest } from './pivots.js';
import { synthesize } from './assessment-report.js';
import { startDashboard } from './dashboard.js';

/**
 * CLI entry point. Multi-command:
 *   run       (default) — run a playbook against a target
 *   diff      — compare two run JSON files
 *   watch     — run a watchlist of targets + playbooks
 *   schedule  — run a playbook on a cron schedule (long-running)
 *   report    — export a run JSON to PDF / DOCX / HTML
 *
 * Backwards compatible: `node src/index.js -p playbook.yaml --target host` (or `cyberagent ...` if installed) still
 * works (it is the default command).
 */

function collectVars(argv) {
  const vars = {};
  (argv.var || []).forEach(kv => {
    const [k, ...rest] = String(kv).split('=');
    vars[k.trim()] = rest.join('=');
  });
  if (argv.target) vars.target = argv.target;
  return vars;
}

// Render a ranked list of pivot suggestions for the CLI.
function printSuggestions(next) {
  if (!next.length) { console.log('  (no suggestions — assessment looks complete)'); return; }
  console.log(`\nNext best actions (${next.length}):`);
  for (const s of next) {
    const o = s.opts && Object.keys(s.opts).length ? ` ${JSON.stringify(s.opts)}` : '';
    console.log(`  [${String(s.priority).padStart(2)}] ${s.uses} → ${s.target}${o}  — ${s.reason}`);
  }
}

// Drive an assessment to completion: run the top-N suggestions round after round
// until the pivot engine is exhausted (or the safety cap is hit). Imported lazily
// inside the command to keep this module's top tidy.
async function driveAssessment(session, catalog, runStep, suggest, saveAssessment, { posture, top, maxRounds }) {
  let round = 0;
  while (round < maxRounds) {
    const batch = suggest(session, catalog, { posture, limit: top });
    if (!batch.length) break;
    round++;
    console.log(`\n── round ${round} (${batch.length} actions) ──`);
    for (const s of batch) {
      process.stdout.write(`▶ ${s.uses} on ${s.target} … `);
      const r = await runStep(session, s, catalog);
      console.log(r.ok ? `ok (+${r.newFindings.length} findings, +${r.newEntities.length} entities)` : `error: ${r.error}`);
    }
    await saveAssessment(session);
  }
  return round;
}

// Wrap an async command handler so any thrown error is reported cleanly and the
// process exits non-zero (yargs does not reliably propagate async rejections).
const wrap = (fn) => async (argv) => {
  try {
    await fn(argv);
  } catch (err) {
    process.stderr.write(`\n❌ ${err?.message || err}\n`);
    process.exit(1);
  }
};

await yargs(hideBin(process.argv))
  .scriptName('cyberagent')
  // ── run (default) ──────────────────────────────────────────────────────────
  .command(
    ['run', '$0'],
    'Run a playbook against a target',
    y => y
      .option('p', { alias: 'playbook', type: 'string', demandOption: true, describe: 'Path to playbook .yaml (or legacy .md) file' })
      .option('target', { alias: 't', type: 'string', describe: 'Recon target (shorthand for --var target=<value>)' })
      .option('var', { type: 'array', describe: 'Override playbook vars, e.g. --var scheme=http' })
      .option('out', { type: 'string', default: './runs', describe: 'Output directory for reports' })
      .option('timeout', { type: 'number', describe: 'Per-step timeout in ms' })
      .option('passive', { type: 'boolean', default: false, describe: 'Passive-only: skip active executors (no packets to the host)' })
      .example('$0 -p playbooks/quick-web-recon.yaml --target fortmind.qa', 'Run a playbook'),
    wrap(async argv => {
      await ensureDir(argv.out);
      const r = await runPlaybook({
        playbookPath: argv.playbook,
        outDir: argv.out,
        varOverrides: collectVars(argv),
        stepTimeoutMs: argv.timeout,
        posture: argv.passive ? 'passive' : undefined,
      });
      process.stderr.write('\n✅ Done.\n');
      console.log(`JSON:     ${r.jsonPath}`);
      console.log(`Markdown: ${r.mdPath}`);
      if (r.report.topSeverity) console.log(`Top severity: ${r.report.topSeverity}`);
      if (r.notification?.sent) console.log(`Notified: ${JSON.stringify(r.notification.results)}`);
    })
  )
  // ── auto ────────────────────────────────────────────────────────────────────
  .command(
    'auto',
    'Auto-select and run every executor applicable to a target (no playbook needed)',
    y => y
      .option('target', { alias: 't', type: 'string', demandOption: true, describe: 'Target (domain / IP / CIDR / URL)' })
      .option('phase', { type: 'string', default: 'reconnaissance', choices: ['reconnaissance', 'scanning', 'gaining-access', 'all'], describe: 'Which phase(s) to run' })
      .option('passive', { type: 'boolean', default: false, describe: 'Passive-only: skip active executors' })
      .option('out', { type: 'string', default: './runs', describe: 'Output directory for reports' })
      .option('timeout', { type: 'number', describe: 'Per-step timeout in ms' })
      .example('$0 auto --target example.com', 'Run all applicable reconnaissance')
      .example('$0 auto --target 192.0.2.0/24 --phase all', 'All applicable executors for a CIDR'),
    wrap(async argv => {
      const catalog = await loadCatalog();
      const posture = argv.passive ? 'passive' : undefined;
      const playbook = assemble(catalog, { target: argv.target, phase: argv.phase, posture });
      if (!playbook.steps.length) {
        process.stderr.write(`No applicable executors for a ${playbook._meta.type} in phase "${argv.phase}".\n`);
        process.exitCode = 1;
        return;
      }
      process.stderr.write(
        `Target "${playbook._meta.host}" → ${playbook._meta.type}; running ${playbook._meta.selected} executor(s) ` +
        `[${argv.phase}${posture ? ', passive' : ''}]\n`);
      await ensureDir(argv.out);
      const r = await runPlaybook({
        playbook, outDir: argv.out,
        varOverrides: { target: playbook.vars.target }, stepTimeoutMs: argv.timeout, posture,
      });
      process.stderr.write('\n✅ Done.\n');
      console.log(`JSON:     ${r.jsonPath}`);
      console.log(`Markdown: ${r.mdPath}`);
      if (r.report.topSeverity) console.log(`Top severity: ${r.report.topSeverity}`);
    })
  )
  // ── diff ────────────────────────────────────────────────────────────────────
  .command(
    'diff <a> <b>',
    'Compare two run JSON files and highlight what changed',
    y => y
      .positional('a', { type: 'string', describe: 'Earlier run JSON' })
      .positional('b', { type: 'string', describe: 'Later run JSON' })
      .option('out', { type: 'string', describe: 'Write the Markdown diff to a file instead of stdout' }),
    wrap(async argv => {
      const diff = await diffFiles(argv.a, argv.b);
      const md = formatDiffMarkdown(diff);
      if (argv.out) {
        await fs.writeFile(argv.out, md);
        console.log(`Diff written: ${argv.out}`);
      } else {
        console.log(md);
      }
      // Non-zero exit when something changed — handy for monitoring/CI.
      process.exitCode = hasChanges(diff) ? 1 : 0;
    })
  )
  // ── watch ───────────────────────────────────────────────────────────────────
  .command(
    'watch',
    'Run a watchlist of targets and playbooks from a YAML file',
    y => y
      .option('list', { type: 'string', demandOption: true, describe: 'Path to a watchlist YAML (e.g. watchlists/example.yaml)' })
      .option('out', { type: 'string', default: './runs', describe: 'Output directory for reports' })
      .option('timeout', { type: 'number', describe: 'Per-step timeout in ms' }),
    wrap(async argv => {
      const res = await runWatchlist({
        listPath: argv.list,
        outDir: argv.out,
        stepTimeoutMs: argv.timeout,
        onProgress: m => process.stderr.write(`▶ ${m}\n`),
      });
      for (const r of res.results) {
        const status = r.ok ? `top=${r.topSeverity || 'none'}` : `ERROR: ${r.error}`;
        console.log(`${r.ok ? '✅' : '❌'} ${r.host} / ${r.playbook} — ${status}`);
      }
      console.log(`\n${res.runs} run(s) across ${res.targets} target(s).`);
    })
  )
  // ── schedule ────────────────────────────────────────────────────────────────
  .command(
    'schedule',
    'Run a playbook against a target on a cron schedule (stays running)',
    y => y
      .option('playbook', { type: 'string', demandOption: true, describe: 'Playbook id or .yaml path' })
      .option('target', { type: 'string', demandOption: true, describe: 'Target host/IP' })
      .option('cron', { type: 'string', demandOption: true, describe: 'Cron expression, e.g. "0 8 * * 1"' })
      .option('out', { type: 'string', default: './runs', describe: 'Output directory for reports' })
      .option('now', { type: 'boolean', default: false, describe: 'Run once immediately, then on schedule' })
      .option('timeout', { type: 'number', describe: 'Per-step timeout in ms' })
      .example('$0 schedule --playbook quick-web-recon --target fortmind.qa --cron "0 8 * * 1"', 'Every Monday 08:00'),
    wrap(async argv => {
      await scheduleScan({
        playbook: argv.playbook,
        target: argv.target,
        cronExpr: argv.cron,
        outDir: argv.out,
        stepTimeoutMs: argv.timeout,
        runImmediately: argv.now,
      });
      await new Promise(() => {}); // keep the process alive for the scheduler
    })
  )
  // ── report ──────────────────────────────────────────────────────────────────
  .command(
    'report <run>',
    'Export a run JSON to a PDF / DOCX / HTML assessment report',
    y => y
      .positional('run', { type: 'string', describe: 'Path to a run JSON file' })
      .option('format', { type: 'string', default: 'pdf', choices: ['pdf', 'docx', 'html'], describe: 'Output format' })
      .option('out', { type: 'string', describe: 'Output file (default: alongside the run JSON)' })
      .option('company', { type: 'string', describe: 'Company name for report branding' })
      .example('$0 report runs/run.json --format pdf --out report.pdf', 'Generate a PDF'),
    wrap(async argv => {
      const out = argv.out || argv.run.replace(/\.json$/i, '') + '.' + argv.format;
      await generateReportFromFile(argv.run, { format: argv.format, out, branding: { company: argv.company } });
      console.log(`Report written: ${out}`);
    })
  )
  // ── capabilities / list ─────────────────────────────────────────────────────
  .command(
    ['capabilities', 'list'],
    'List every executor grouped by phase / posture / domain',
    y => y.option('json', { type: 'boolean', default: false, describe: 'Output the raw catalog as JSON' }),
    wrap(async argv => {
      const catalog = await loadCatalog();
      if (argv.json) {
        console.log(JSON.stringify({
          executors: catalog.executors,
          byPhase: Object.fromEntries(Object.entries(catalog.byPhase).map(([k, v]) => [k, v.map(e => e.uses)])),
        }, null, 2));
        return;
      }
      console.log(`CyberAgentToolSet (CATS) — ${catalog.executors.length} executors across ${catalog.descriptors.length} extensions\n`);
      for (const phase of ['reconnaissance', 'scanning', 'gaining-access']) {
        const list = catalog.byPhase[phase] || [];
        if (!list.length) continue;
        console.log(`${phase.toUpperCase()} (${list.length})`);
        for (const posture of ['passive', 'active']) {
          const sub = list.filter(e => e.posture === posture);
          if (!sub.length) continue;
          console.log(`  ${posture}:`);
          const byDomain = {};
          for (const e of sub) (byDomain[e.domain] ||= []).push(e.uses);
          for (const d of Object.keys(byDomain).sort()) {
            console.log(`    ${d.padEnd(15)} ${byDomain[d].sort().join(', ')}`);
          }
        }
        console.log('');
      }
    })
  )

  // ── permissions ─────────────────────────────────────────────────────────────
  .command(
    ['permissions', 'perms'],
    'Show each extension\'s declared permissions (network / env / bins)',
    y => y.option('json', { type: 'boolean', default: false, describe: 'Output permissions as JSON' }),
    wrap(async argv => {
      const catalog = await loadCatalog();
      const rows = catalog.descriptors.map(d => ({
        extension: d.name,
        version: d.version,
        network: d.permissions?.network || [],
        env: d.permissions?.env || [],
        bins: d.permissions?.bins || [],
      })).sort((a, b) => a.extension.localeCompare(b.extension));

      if (argv.json) { console.log(JSON.stringify(rows, null, 2)); return; }

      console.log(`Declared permissions — ${rows.length} extensions`);
      console.log('(strict enforcement: set CATS_STRICT_PERMISSIONS=1 — undeclared env/bin access then throws)\n');
      for (const r of rows) {
        const fmt = (a) => a.length ? a.join(', ') : '—';
        console.log(`${r.extension.padEnd(16)} net: ${fmt(r.network).padEnd(22)} env: ${fmt(r.env).padEnd(34)} bins: ${fmt(r.bins)}`);
      }
    })
  )

  // ── assess (stateful, agent-style assessment) ───────────────────────────────
  .command(
    'assess <action> [idOrTarget]',
    'Stateful recon assessment: start · next · run · report · list',
    y => y
      .positional('action', { choices: ['start', 'next', 'run', 'report', 'list'], describe: 'Assessment action' })
      .positional('idOrTarget', { type: 'string', describe: 'Target (start) or assessment id (next/run/report)' })
      .option('passive', { type: 'boolean', default: false, describe: 'Passive-only: restrict to passive executors' })
      .option('top', { type: 'number', default: 5, describe: 'How many top suggestions to run per round' })
      .option('full', { type: 'boolean', default: false, describe: 'Drive to completion — loop until no pivots remain (start/run)' })
      .option('max-rounds', { type: 'number', default: 12, describe: 'Safety cap on --full rounds. Default: 12' })
      .option('uses', { type: 'string', describe: 'Run a specific executor (with --on)' })
      .option('on', { type: 'string', describe: 'Target for --uses (defaults to the assessment target)' })
      .option('json', { type: 'boolean', default: false, describe: 'JSON output (report/next)' })
      .option('out', { type: 'string', describe: 'Write the report to a file (report)' }),
    wrap(async argv => {
      const posture = argv.passive ? 'passive' : undefined;

      if (argv.action === 'list') {
        const rows = await listAssessments();
        if (argv.json) { console.log(JSON.stringify(rows, null, 2)); return; }
        if (!rows.length) { console.log('No assessments yet. Start one: cyberagent assess start <target>'); return; }
        for (const r of rows) console.log(`${r.id}  ${String(r.target).padEnd(28)} ${r.status.padEnd(7)} ${r.steps} steps · ${r.findings} findings · ${r.updatedAt}`);
        return;
      }

      const catalog = await loadCatalog();

      if (argv.action === 'start') {
        if (!argv.idOrTarget) throw new Error('assess start needs a target: cyberagent assess start example.com');
        const session = createAssessment({ target: argv.idOrTarget, posture });
        const reach = await preflightTarget(session);
        await saveAssessment(session);
        console.log(`✅ Assessment ${session.id} started for ${session.target} (${session.targetType})`);
        if (!reach.resolves) {
          console.log(`\n⚠ Target does not resolve (${reach.reason}) — likely a typo or nonexistent. ` +
            `Passive sources will find little; double-check the hostname.`);
        }
        if (argv.full && reach.resolves) {
          const rounds = await driveAssessment(session, catalog, runStep, suggest, saveAssessment, { posture, top: argv.top, maxRounds: argv['max-rounds'] });
          console.log(`\n✅ Full assessment complete (${rounds} rounds, ${session.steps.length} steps, ${session.findings.length} findings).`);
          console.log(`Report: cyberagent assess report ${session.id}`);
          return;
        }
        const next = suggest(session, catalog, { posture, limit: argv.top });
        printSuggestions(next);
        console.log(`\nRun the top ${argv.top}:  cyberagent assess run ${session.id} --top ${argv.top}${argv.passive ? ' --passive' : ''}`);
        console.log(`Or run the whole thing:  cyberagent assess start ${session.target} --full${argv.passive ? ' --passive' : ''}`);
        return;
      }

      const session = await loadAssessment(argv.idOrTarget);
      if (!session) throw new Error(`Assessment "${argv.idOrTarget}" not found (try: cyberagent assess list)`);

      if (argv.action === 'next') {
        const next = suggest(session, catalog, { posture, limit: argv.top });
        if (argv.json) { console.log(JSON.stringify(next, null, 2)); return; }
        printSuggestions(next);
        return;
      }

      if (argv.action === 'run') {
        if (argv.full && !argv.uses) {
          const rounds = await driveAssessment(session, catalog, runStep, suggest, saveAssessment, { posture, top: argv.top, maxRounds: argv['max-rounds'] });
          console.log(`\n✅ Full assessment complete (${rounds} rounds, ${session.steps.length} steps, ${session.findings.length} findings).`);
          console.log(`Report: cyberagent assess report ${session.id}`);
          return;
        }
        let toRun;
        if (argv.uses) {
          toRun = [{ uses: argv.uses, target: argv.on || session.target, opts: {} }];
        } else {
          toRun = suggest(session, catalog, { posture, limit: argv.top });
        }
        if (!toRun.length) { console.log('Nothing to run — no suggestions left. View the report: cyberagent assess report ' + session.id); return; }
        for (const s of toRun) {
          process.stdout.write(`▶ ${s.uses} on ${s.target} … `);
          const r = await runStep(session, s, catalog);
          console.log(r.ok ? `ok (+${r.newFindings.length} findings, +${r.newEntities.length} entities)` : `error: ${r.error}`);
        }
        await saveAssessment(session);
        const next = suggest(session, catalog, { posture, limit: argv.top });
        console.log('');
        printSuggestions(next);
        console.log(`\nReport: cyberagent assess report ${session.id}`);
        return;
      }

      if (argv.action === 'report') {
        const { json, markdown } = synthesize(session);
        if (argv.out) { await fs.writeFile(argv.out, markdown); console.log(`Report written to ${argv.out}`); return; }
        console.log(argv.json ? JSON.stringify(json, null, 2) : markdown);
        return;
      }
    })
  )
  // ── dashboard ───────────────────────────────────────────────────────────────
  .command(
    'dashboard',
    'Launch the local web dashboard (browse assessments/runs, drive an assessment)',
    y => y
      .option('port', { type: 'number', default: 7878, describe: 'Port. Default: 7878' })
      .option('host', { type: 'string', default: '127.0.0.1', describe: 'Bind host. Default: 127.0.0.1 (localhost)' }),
    wrap(async argv => {
      const { url } = await startDashboard({ port: argv.port, host: argv.host });
      console.log(`\n  CyberAgentToolSet dashboard → ${url}`);
      console.log('  Browse assessments & runs, view reports, diff runs, drive an assessment.');
      console.log('  Localhost-only by design; it can trigger active scans. Ctrl-C to stop.\n');
    })
  )
  .strict()
  .help()
  .alias('help', 'h')
  .parseAsync();
