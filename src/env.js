/**
 * Loads the project `.env` so API keys (SHODAN_API_KEY, ABUSEIPDB_API_KEY,
 * NVD_API_KEY) and notification config (SLACK_WEBHOOK_URL, …) work out of the
 * box for both out-of-the-box and npm-installed extensions.
 *
 * Import this FIRST (before the runner/loader) at every entry point. The path is
 * resolved relative to this file, so it works no matter what cwd the CLI or the
 * MCP server is launched from. Real environment variables always win over .env.
 */
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// quiet: dotenv's startup banner would otherwise corrupt the MCP server's stdio
// JSON-RPC stream.
dotenv.config({ path: path.join(__dirname, '..', '.env'), quiet: true });
