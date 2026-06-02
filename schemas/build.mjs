// Regenerate the playbook schema's `uses` enum from the live extension catalog.
// Run after adding/removing executors:  node schemas/build.mjs
import fs from 'fs';
import { loadCatalog } from '../src/extensions/loader.js';

const c = await loadCatalog();
const uses = [...new Set(c.executors.map(e => e.uses))].sort();
const path = new URL('./playbook.schema.json', import.meta.url);
const schema = JSON.parse(fs.readFileSync(path, 'utf8'));
schema.properties.steps.items.properties.uses.enum = uses;
fs.writeFileSync(path, JSON.stringify(schema, null, 2) + '\n');
console.log(`playbook.schema.json uses-enum updated: ${uses.length} executors`);
