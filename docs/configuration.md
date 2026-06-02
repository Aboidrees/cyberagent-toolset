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
node src/index.js -p playbooks/quick-web-recon.yaml --target example.com

# Full control
node src/index.js -p playbooks/web-basic-recon.yaml \
  --target example.com \
  --var scheme=http \
  --var topPorts=500 \
  --timeout 20000 \
  --out ./results/2026-04

# Multiple --var overrides
node src/index.js -p playbooks/comprehensive-web-recon.yaml \
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
node src/index.js -p playbooks/quick-web-recon.yaml --target example.com --out ./reports/q1
```

Filenames are timestamped:

```TEXT
runs/Quick_Web_Reconnaissance_2026-04-06T11-30-00-000Z.json
runs/Quick_Web_Reconnaissance_2026-04-06T11-30-00-000Z.md
```

The `runs/` directory is gitignored — reports are never committed to source control.

---

## Environment variables

Create a `.env` file in the project root (it is gitignored). Everything is
optional — the tool runs fully keyless. See `.env.example` for the full list.

```bash
# .env

# ── Webhook / notifications ──
# A run summary is POSTed when findings meet the severity threshold.
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
WEBHOOK_URL=https://example.com/recon-webhook
NOTIFY_ON_SEVERITY=high,critical        # comma list, or "all"

# ── Optional API keys for key-gated executors ──
ABUSEIPDB_API_KEY=your_key_here          # ip.intel abuse reputation (optional)
SHODAN_API_KEY=your_key_here             # shodan.host (no-op without it)
NVD_API_KEY=your_key_here                # vuln.cve_lookup rate-limit boost (optional)
```

All built-in executors work without keys; the keys above only enable extra
enrichment or integrations.

---

## CLI commands

Beyond the default `run` command, the CLI exposes scale-and-automation commands:

```bash
# Run a playbook (default command — the bare form still works)
node src/index.js -p playbooks/quick-web-recon.yaml --target fortmind.qa

# Diff two runs — exits non-zero when something changed (handy for monitoring)
node src/index.js diff runs/old.json runs/new.json [--out diff.md]

# Run a batch of targets + playbooks from a YAML watchlist
node src/index.js watch --list watchlists/example.yaml [--out ./runs]

# Run a playbook on a cron schedule (long-running; new findings fire webhooks)
node src/index.js schedule --playbook quick-web-recon --target fortmind.qa \
  --cron "0 8 * * 1" [--now]

# Export a run to a professional report
node src/index.js report runs/run.json --format pdf --out report.pdf [--company "Acme"]
```

`npm run diff|watch|schedule|report` are shortcuts for the same commands.

## Parallel step execution

Mark steps with `parallel: true` to run consecutive parallel steps concurrently.
A non-parallel step acts as a barrier; output order always matches declaration
order.

```yaml
steps:
  - name: DNS Records
    uses: dns.resolve
    parallel: true        # runs at the same time as the next parallel step
  - name: WHOIS
    uses: whois.lookup
    parallel: true
  - name: Port Scan       # barrier — waits for the parallel batch above
    uses: nmap.scan
```

---

## MCP server configuration

The MCP server has no separate config file. It reads playbooks dynamically from `playbooks/` at startup. To change behaviour:

- **Add/remove playbooks** — drop or delete `.yaml` files in `playbooks/`, restart the server
- **Change the runs directory** — edit the `RUNS_DIR` constant at the top of `src/mcp-server.js`
- **Change the playbooks directory** — edit `PLAYBOOKS_DIR` in `src/utils/playbooks.js`

See [MCP Integration](mcp-integration.md) for Claude Desktop configuration.
