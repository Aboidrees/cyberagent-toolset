/**
 * Playbook loader — scans the playbooks/ directory at runtime and
 * returns rich metadata for each playbook. Used by the MCP server to
 * dynamically register one tool per playbook so the tool list always
 * reflects whatever .md files are on disk (no code changes needed to
 * add or remove playbooks).
 */

import fs from 'fs/promises';
import path from 'path';
import matter from 'gray-matter';
import yaml from 'js-yaml';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const PLAYBOOKS_DIR = path.join(__dirname, '..', '..', 'playbooks');

/**
 * Directories scanned for playbooks, in priority order (a later directory wins
 * on id collision): the bundled playbooks/ first, then an optional user dir from
 * CATS_PLAYBOOKS_DIR. This lets a globally-installed CLI or MCP server expose
 * custom playbooks without modifying the package — drop .yaml files in the dir
 * named by CATS_PLAYBOOKS_DIR and they appear alongside the built-ins.
 */
export function playbookDirs() {
  const dirs = [PLAYBOOKS_DIR];
  if (process.env.CATS_PLAYBOOKS_DIR) dirs.push(path.resolve(process.env.CATS_PLAYBOOKS_DIR));
  return dirs;
}

/**
 * Resolve a `-p` / `--playbook` argument to an absolute playbook file path.
 *
 * Accepts either:
 *   - a path to an existing .yaml/.yml/.md file (relative or absolute), or
 *   - a bare playbook id (e.g. "quick-web-recon"), resolved against the
 *     bundled playbooks/ directory — so it works the same whether CATS is run
 *     from source or installed globally (where the cwd has no playbooks/).
 *
 * Throws with the list of available ids when nothing matches.
 */
export async function resolvePlaybook(arg) {
  if (!arg) throw new Error('No playbook given. Pass a playbook id (e.g. "quick-web-recon") or a path to a .yaml file.');

  // 1) An existing file path wins (covers .yaml/.yml/.md, relative or absolute).
  const asPath = path.resolve(arg);
  try {
    if ((await fs.stat(asPath)).isFile()) return asPath;
  } catch { /* not a file — fall through to id resolution */ }

  // 2) Treat it as an id. Strip a trailing extension so "quick-web-recon.yaml"
  //    (without the dir) still resolves by id.
  const id = arg.replace(/\.(ya?ml|md)$/i, '');
  const all = await loadPlaybooks();
  const pb = all.find(p => p.id === id);
  if (pb) return pb.file;

  throw new Error(
    `Playbook "${arg}" not found. Pass a .yaml path or one of these ids:\n  ${all.map(p => p.id).join('\n  ')}`
  );
}

/**
 * Convert a playbook id like "web-basic-recon" to a safe MCP tool
 * name suffix like "web_basic_recon".
 */
export function idToToolName(id) {
  return id.replace(/[^a-zA-Z0-9]/g, '_');
}

/**
 * Convert an MCP tool name suffix back to a playbook id.
 * e.g. "web_basic_recon" → "web-basic-recon"
 * This is a best-effort reverse — we look up by scanning PLAYBOOKS.
 */
export function toolNameToId(toolSuffix) {
  // Replace underscores with hyphens as the canonical form
  return toolSuffix.replace(/_/g, '-');
}

/**
 * Load all playbooks from the playbooks/ directory.
 * Skips files starting with "_" (templates / partials).
 *
 * Returns an array of:
 * {
 *   id:          string   — from YAML front matter (e.g. "web-basic-recon")
 *   title:       string   — human label (e.g. "Basic Web Recon")
 *   description: string   — first paragraph of body content
 *   file:        string   — absolute path to .md file
 *   filename:    string   — just the filename
 *   toolName:    string   — safe MCP tool name suffix
 *   defaultVars: object   — default variable values from front matter
 *   stepCount:   number   — how many steps the playbook has
 *   steps:       string[] — step names in order
 *   executors:   string[] — unique executor types used (e.g. dns.resolve, nmap.scan)
 * }
 */
export async function loadPlaybooks() {
  // Keyed by id so a user playbook (later dir) overrides a built-in with the
  // same id. Built-ins are scanned first, user dir second.
  const byId = new Map();

  // Playbooks are .yaml/.yml (pure YAML) or .md (YAML front matter + body, legacy).
  // Files starting with "_" are templates/partials and are skipped.
  const isPlaybook = f =>
    !f.startsWith('_') && (f.endsWith('.yaml') || f.endsWith('.yml') || f.endsWith('.md'));

  for (const dir of playbookDirs()) {
    const builtin = dir === PLAYBOOKS_DIR;
    let files;
    try {
      files = await fs.readdir(dir);
    } catch {
      continue; // missing/unreadable dir (e.g. a mistyped CATS_PLAYBOOKS_DIR) — skip quietly
    }

    for (const file of files.filter(isPlaybook)) {
      const filepath = path.join(dir, file);
      try {
        const raw = await fs.readFile(filepath, 'utf8');

        let fm, content = '';
        if (file.endsWith('.md')) {
          const parsed = matter(raw, { engines: { yaml: s => yaml.load(s) } });
          fm = parsed.data;
          content = parsed.content;
        } else {
          fm = yaml.load(raw) || {};
        }

        // Must have an id and title to be usable as an MCP tool
        if (!fm.id || !fm.title) continue;

        // Description: explicit `description:` field wins; otherwise (for legacy .md)
        // fall back to the first non-heading line of the body.
        const descLine = content
          .split('\n')
          .map(l => l.trim())
          .find(l => l.length > 0 && !l.startsWith('#') && !l.startsWith('```'));

        const description = fm.description || descLine || `Run ${fm.title} checks against a target.`;

        const steps = (fm.steps || []);
        const executors = [...new Set(steps.map(s => s.uses).filter(Boolean))];

        byId.set(fm.id, {
          id: fm.id,
          title: fm.title,
          description: description.replace(/\{\{[^}]+\}\}/g, '<target>'), // clean template vars
          file: filepath,
          filename: file,
          builtin,
          toolName: idToToolName(fm.id),
          defaultVars: fm.vars || {},
          stepCount: steps.length,
          steps: steps.map(s => s.name).filter(Boolean),
          executors,
        });
      } catch {
        // Skip malformed playbooks silently
      }
    }
  }

  return [...byId.values()].sort((a, b) => a.title.localeCompare(b.title));
}
