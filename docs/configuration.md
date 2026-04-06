# Configuration

## CLI flags

| Flag | Short | Type | Default | Description |
| ------ | ------- | ------ | --------- | ------------- |
| `--playbook` | `-p` | string | *(required)* | Path to playbook `.md` file |
| `--target` | `-t` | string | — | Recon target. Shorthand for `--var target=<value>` |
| `--var` | — | array | — | Override playbook variables: `--var key=value` |
| `--out` | — | string | `./runs` | Directory where JSON + Markdown reports are saved |
| `--timeout` | — | number | — | Per-step timeout in milliseconds (overridden by step-level `timeoutMs`) |
| `--help` | — | — | — | Print usage |

### Examples

```bash
# Minimal — target via --target flag
node src/index.js -p playbooks/quick-web-recon.md --target example.com

# Full control
node src/index.js -p playbooks/web-basic-recon.md \
  --target example.com \
  --var scheme=http \
  --var topPorts=500 \
  --timeout 20000 \
  --out ./results/2026-04

# Multiple --var overrides
node src/index.js -p playbooks/comprehensive-web-recon.md \
  --var target=api.example.com \
  --var scheme=https \
  --var deepScan=true
```

---

## Timeout hierarchy

Timeouts are resolved in this order (first match wins):

1. **Step-level** `with.timeoutMs` in the playbook YAML
2. **CLI** `--timeout <ms>` global override
3. **Executor default** (e.g. 5 min for nmap, 10 s for HTTP)

```yaml
# Step-level timeout takes highest priority
- name: Port Scan
  uses: nmap.scan
  with:
    flags: "-sT --top-ports 1000"
    timeoutMs: 120000   # 2 minutes — overrides --timeout flag
```

---

## Output directory

Reports are saved to `./runs/` by default. The directory is created automatically if it does not exist.

```bash
# Save to a custom directory
node src/index.js -p playbooks/quick-web-recon.md --target example.com --out ./reports/q1
```

Filenames are timestamped:

```TEXT
runs/Quick_Web_Reconnaissance_2026-04-06T11-30-00-000Z.json
runs/Quick_Web_Reconnaissance_2026-04-06T11-30-00-000Z.md
```

The `runs/` directory is gitignored — reports are never committed to source control.

---

## Environment variables

Create a `.env` file in the project root (it is gitignored):

```bash
# .env
# Reserved for future API integrations

# SecurityTrails API key (when SecurityTrails executor is added)
# SECURITYTRAILS_API_KEY=your_key_here

# Shodan API key (when Shodan executor is added)
# SHODAN_API_KEY=your_key_here
```

The project does not currently require any API keys — all built-in executors use public APIs or local tools.

---

## MCP server configuration

The MCP server has no separate config file. It reads playbooks dynamically from `playbooks/` at startup. To change behaviour:

- **Add/remove playbooks** — drop or delete `.md` files in `playbooks/`, restart the server
- **Change the runs directory** — edit the `RUNS_DIR` constant at the top of `src/mcp-server.js`
- **Change the playbooks directory** — edit `PLAYBOOKS_DIR` in `src/utils/playbooks.js`

See [MCP Integration](mcp-integration.md) for Claude Desktop configuration.
