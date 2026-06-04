/**
 * Loads API keys (SHODAN_API_KEY, ABUSEIPDB_API_KEY, …), notification config
 * (SLACK_WEBHOOK_URL, …) and path overrides (CATS_PLAYBOOKS_DIR, CATS_RUNS_DIR)
 * so they work for both source checkouts and globally-installed npm packages.
 *
 * Import this FIRST (before the runner/loader) at every entry point.
 *
 * Resolution, highest priority first (a value already set is never overwritten):
 *   1. Real environment variables — exported in your shell (~/.zshrc, ~/.bashrc)
 *      or injected by the MCP client. These ALWAYS win.
 *   2. <cwd>/.env             — project-local, for running from a source checkout.
 *   3. ~/.cyberagent/.env     — per-user config; the recommended place for a
 *                               global install (survives package reinstalls).
 *   4. <package>/.env         — bundled fallback (dev convenience).
 *
 * dotenv does not override variables that are already set, so the first source
 * to define a key wins. All paths are absolute, so this works regardless of the
 * cwd the CLI or MCP server is launched from.
 */
import dotenv from 'dotenv';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// quiet: dotenv's startup banner would otherwise corrupt the MCP server's stdio
// JSON-RPC stream.
const envFiles = [
  path.resolve(process.cwd(), '.env'),
  path.join(os.homedir(), '.cyberagent', '.env'),
  path.join(__dirname, '..', '.env'),
];
for (const file of envFiles) {
  dotenv.config({ path: file, quiet: true });
}
