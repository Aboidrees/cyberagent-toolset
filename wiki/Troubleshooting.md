# Troubleshooting

## Claude shows no tools after restart

- The path in `claude_desktop_config.json` must be **absolute**.
- Run `node /your/path/src/mcp-server.js` manually — it should print
  `CyberAgentToolSet (CATS) v0.22.0 ready — 86 tools, 4 prompts, resources on`.
- Check Claude logs: `~/Library/Logs/Claude/` (macOS).

## A key-gated executor returns a "skipped" note

- `shodan.host`, and `ip.intel` abuse reputation, need keys. Set them in `.env`
  (see [[API Keys]]). `.env` loads automatically.

## `nmap` / `traceroute` step fails

- Install the binary: `brew install nmap` (macOS) / `apt install nmap traceroute`.

## A multi-request step times out

- `http.fuzz_paths`, `http.methods`, and `cloud.bucket_finder` use a per-request
  timeout (`requestTimeoutMs`) separate from the step budget (`timeoutMs`). Raise
  the step `timeoutMs` for slow targets.

## TLS deep can't probe legacy-only servers

- A server that *only* speaks fully-removed algorithms (e.g. raw RC4-MD5) may be
  unreachable from a modern OpenSSL 3 client; this is reported as "could not
  complete a TLS handshake", not a false negative.

## Extension not loading

- Local: it must be `extensions/<dir>/index.js` default-exporting a descriptor with
  `{ name, executors[] }`. Names starting with `_` are skipped.
- NPM: the package name must match `cyberagent-ext-*` / `@cyberagent/ext-*`.
