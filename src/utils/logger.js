/**
 * Step progress logger.
 *
 * IMPORTANT: writes to stderr, NOT stdout.
 * The MCP server uses stdio (stdout) as its JSON-RPC transport — any
 * console.log / process.stdout.write call from application code will
 * corrupt the protocol framing. All human-readable output must go to stderr.
 */
export function logStep(i, name, uses) {
  process.stderr.write(`\n[${String(i).padStart(2, '0')}] ${name}  (${uses})\n`);
}
