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
  let files;
  try {
    files = await fs.readdir(PLAYBOOKS_DIR);
  } catch {
    return [];
  }

  const playbooks = [];

  for (const file of files.filter(f => f.endsWith('.md') && !f.startsWith('_'))) {
    const filepath = path.join(PLAYBOOKS_DIR, file);
    try {
      const raw = await fs.readFile(filepath, 'utf8');
      const { data: fm, content } = matter(raw, {
        engines: { yaml: s => yaml.load(s) },
      });

      // Must have an id and title to be usable as an MCP tool
      if (!fm.id || !fm.title) continue;

      // Extract description: first non-heading, non-empty line from body
      const descLine = content
        .split('\n')
        .map(l => l.trim())
        .find(l => l.length > 0 && !l.startsWith('#') && !l.startsWith('```'));

      const description = descLine || `Run ${fm.title} checks against a target.`;

      const steps = (fm.steps || []);
      const executors = [...new Set(steps.map(s => s.uses).filter(Boolean))];

      playbooks.push({
        id: fm.id,
        title: fm.title,
        description: description.replace(/\{\{[^}]+\}\}/g, '<target>'), // clean template vars
        file: filepath,
        filename: file,
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

  return playbooks.sort((a, b) => a.title.localeCompare(b.title));
}
