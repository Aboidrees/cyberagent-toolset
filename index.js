import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { runPlaybook } from './runner.js';
import { ensureDir } from './utils/fsx.js';

// CLI entrypoint for the recon runner
const argv = yargs(hideBin(process.argv))
  .option('p', { alias: 'playbook', type: 'string', demandOption: true, describe: 'Path to playbook .md' })
  .option('var', { type: 'array', describe: 'Override vars, e.g. --var target=acme.com --var scheme=http' })
  .option('out', { type: 'string', default: './runs', describe: 'Output directory' })
  .help().argv;

const varOverrides = {};
(argv.var || []).forEach(kv => {
  const [k, ...rest] = String(kv).split('=');
  varOverrides[k] = rest.join('='); // support values with '='
});

await ensureDir(argv.out);

const result = await runPlaybook({
  playbookPath: argv.playbook,
  outDir: argv.out,
  varOverrides
});

console.log(`\n✅ Done. JSON: ${result.jsonPath}\n📝 Markdown: ${result.mdPath}`);