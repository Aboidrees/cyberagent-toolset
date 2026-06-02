import fs from 'fs/promises';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { runPlaybook } from './runner.js';
import { diffFiles, formatDiffMarkdown, hasChanges } from './diff.js';
import { runWatchlist } from './watch.js';
import { scheduleScan } from './schedule.js';
import { generateReportFromFile } from './report.js';
import { ensureDir } from './utils/fsx.js';

/**
 * CLI entry point. Multi-command:
 *   run       (default) — run a playbook against a target
 *   diff      — compare two run JSON files
 *   watch     — run a watchlist of targets + playbooks
 *   schedule  — run a playbook on a cron schedule (long-running)
 *   report    — export a run JSON to PDF / DOCX / HTML
 *
 * Backwards compatible: `node src/index.js -p playbook.yaml --target host` still
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
  .scriptName('mcp-recon')
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
      .example('$0 -p playbooks/quick-web-recon.yaml --target fortmind.qa', 'Run a playbook'),
    wrap(async argv => {
      await ensureDir(argv.out);
      const r = await runPlaybook({
        playbookPath: argv.playbook,
        outDir: argv.out,
        varOverrides: collectVars(argv),
        stepTimeoutMs: argv.timeout,
      });
      process.stderr.write('\n✅ Done.\n');
      console.log(`JSON:     ${r.jsonPath}`);
      console.log(`Markdown: ${r.mdPath}`);
      if (r.report.topSeverity) console.log(`Top severity: ${r.report.topSeverity}`);
      if (r.notification?.sent) console.log(`Notified: ${JSON.stringify(r.notification.results)}`);
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
  .strict()
  .help()
  .alias('help', 'h')
  .parseAsync();
