// Deterministic CI gate — no external network needed.
// Asserts the engine's structural invariants: the catalog loads, every executor
// is registered with a run function and a unique uses key, every playbook step
// and watchlist entry resolves, and the playbook schema's uses-enum matches the
// catalog (catches drift when executors are added without rebuilding the schema).
//
//   node scripts/ci-validate.mjs   →  exit 0 on success, 1 on any failure

import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';
import { loadCatalog } from '../src/extensions/loader.js';
import { loadPlaybooks } from '../src/utils/playbooks.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
let failures = 0;
const fail = (m) => { console.error('✗', m); failures++; };
const ok = (m) => console.log('✓', m);

const catalog = await loadCatalog();
const reg = new Set(Object.keys(catalog.registry));

// 1. Executors: present, unique, runnable.
catalog.executors.length
  ? ok(`${catalog.executors.length} executors across ${catalog.descriptors.length} extensions`)
  : fail('no executors loaded');

const usesList = catalog.executors.map(e => e.uses);
const dupes = usesList.filter((u, i) => usesList.indexOf(u) !== i);
dupes.length ? fail(`duplicate uses keys: ${[...new Set(dupes)].join(', ')}`) : ok('no duplicate uses keys');

const noRun = catalog.executors.filter(e => typeof catalog.registry[e.uses] !== 'function');
noRun.length ? fail(`executors missing run(): ${noRun.map(e => e.uses).join(', ')}`) : ok('every executor has a run function');

// 2. Every playbook step resolves to a registered executor.
const playbooks = await loadPlaybooks();
let pbBad = 0;
for (const pb of playbooks) {
  const fm = yaml.load(fs.readFileSync(pb.file, 'utf8'));
  for (const s of fm.steps || []) {
    if (s.uses && !reg.has(s.uses)) { fail(`playbook "${pb.id}" → unknown uses "${s.uses}"`); pbBad++; }
  }
}
if (!pbBad) ok(`${playbooks.length} playbooks — all step uses resolve`);

// 3. Every watchlist references existing playbooks.
const ids = new Set(playbooks.map(p => p.id));
let wlBad = 0;
const wlDir = path.join(ROOT, 'watchlists');
for (const f of (fs.existsSync(wlDir) ? fs.readdirSync(wlDir) : []).filter(x => x.endsWith('.yaml'))) {
  const wl = yaml.load(fs.readFileSync(path.join(wlDir, f), 'utf8'));
  for (const t of wl.targets || []) for (const id of t.playbooks || []) {
    if (!ids.has(id)) { fail(`watchlist "${f}" → unknown playbook "${id}"`); wlBad++; }
  }
}
if (!wlBad) ok('watchlists — all playbook ids resolve');

// 4. Playbook schema uses-enum matches the catalog exactly.
const schema = JSON.parse(fs.readFileSync(path.join(ROOT, 'schemas/playbook.schema.json'), 'utf8'));
const enumSet = new Set(schema.properties.steps.items.properties.uses.enum);
const missing = [...reg].filter(u => !enumSet.has(u));
const extra = [...enumSet].filter(u => !reg.has(u));
(missing.length || extra.length)
  ? fail(`schema uses-enum drift — missing: [${missing}] extra: [${extra}] (run: node schemas/build.mjs)`)
  : ok('schema uses-enum matches the catalog');

console.log(failures ? `\n${failures} check(s) failed` : '\nAll validation checks passed.');
process.exit(failures ? 1 : 0);
