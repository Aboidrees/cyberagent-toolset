import fs from 'fs/promises';

// Ensure a directory exists, creating it recursively if necessary
export async function ensureDir(p) {
  await fs.mkdir(p, { recursive: true });
}

// Generate a filename prefix with ISO timestamp (replacing disallowed characters)
export function timestampFile(prefix) {
  const t = new Date().toISOString().replace(/[:.]/g, '-');
  return `${prefix}_${t}`;
}