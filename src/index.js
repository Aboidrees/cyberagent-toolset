import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { runPlaybook } from './runner.js';
import { ensureDir } from './utils/fsx.js';

/**
 * CLI entry point for the recon runner.
 *
 * Usage examples:
 *   node src/index.js -p playbooks/quick-web-recon.md --target cyberany.org
 *   node src/index.js -p playbooks/web-basic-recon.md --var target=acme.com --var scheme=http
 */
const argv = yargs(hideBin(process.argv))
  .option('p', {
    alias: 'playbook',
    type: 'string',
    demandOption: true,
    describe: 'Path to playbook .md file',
  })
  .option('target', {
    alias: 't',
    type: 'string',
    describe: 'Recon target (hostname or IP). Shorthand for --var target=<value>',
  })
  .option('var', {
    type: 'array',
    describe: 'Override playbook vars, e.g. --var scheme=http --var topPorts=500',
  })
  .option('out', {
    type: 'string',
    default: './runs',
    describe: 'Output directory for JSON + Markdown reports',
  })
  .option('timeout', {
    type: 'number',
    describe: 'Per-step timeout in ms (can be overridden per-step in the playbook)',
  })
  .example('$0 -p playbooks/quick-web-recon.md --target cyberany.org')
  .example('$0 -p playbooks/web-basic-recon.md --var target=acme.com --var scheme=http')
  .help()
  .argv;

// Build varOverrides: --target takes precedence, then --var entries
const varOverrides = {};

(argv.var || []).forEach(kv => {
  const [k, ...rest] = String(kv).split('=');
  varOverrides[k.trim()] = rest.join('=');
});

if (argv.target) {
  varOverrides.target = argv.target;
}

await ensureDir(argv.out);

const result = await runPlaybook({
  playbookPath:  argv.playbook,
  outDir:        argv.out,
  varOverrides,
  stepTimeoutMs: argv.timeout,
});

process.stderr.write(`\n✅ Done.\n`);
console.log(`JSON:     ${result.jsonPath}`);
console.log(`Markdown: ${result.mdPath}`);
