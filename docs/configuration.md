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

The directory is created automatically if it does not exist. Resolution order:

1. **`--out <dir>`** flag (CLI, per-invocation) — highest priority.
2. **`CATS_RUNS_DIR`** env var — applies to the CLI default *and* the MCP server.
3. Default: **`./runs/`** for the CLI (relative to cwd), and **`~/.cyberagent/runs`**
   for the MCP server (so a global server never writes inside its own package dir).

```bash
# Save to a custom directory (one run)
cyberagent -p quick-web-recon --target example.com --out ./reports/q1

# Set a default for every run (CLI + MCP)
export CATS_RUNS_DIR="$HOME/recon/runs"
```

Filenames are timestamped:

```TEXT
runs/Quick_Web_Reconnaissance_2026-04-06T11-30-00-000Z.json
runs/Quick_Web_Reconnaissance_2026-04-06T11-30-00-000Z.md
```

The `runs/` directory is gitignored — reports are never committed to source control.

---

## Environment variables

Everything is optional — the tool runs fully keyless. Keys only enable extra
enrichment (Shodan, VirusTotal, …) or notifications.

### How to set them

CATS reads variables from several sources at startup, in priority order (a value
already set is **never** overwritten, so the first source to define a key wins):

| Priority | Source | Best for |
| -------- | ------ | -------- |
| 1 (highest) | **Real shell environment** — `export` in `~/.zshrc` / `~/.bashrc` | CLI usage; persists across sessions |
| 2 | **`<cwd>/.env`** — a `.env` in the directory you run from | Source checkouts / per-project keys |
| 3 | **`~/.cyberagent/.env`** — a per-user file | **Global installs** (survives `npm` reinstalls) |
| 4 (lowest) | **`<package>/.env`** — bundled file | Dev convenience |

**Option A — shell profile (recommended for the CLI).** Add exports to your shell
rc file so every terminal session has them:

```bash
# ~/.zshrc  or  ~/.bashrc
export SHODAN_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export CATS_PLAYBOOKS_DIR="$HOME/recon/playbooks"
export CATS_RUNS_DIR="$HOME/recon/runs"
```

Then reload: `source ~/.zshrc` (or open a new terminal). Verify with
`echo $SHODAN_API_KEY`.

> **MCP note:** GUI apps like Claude Desktop do **not** read `~/.zshrc`, so shell
> exports won't reach a GUI-launched MCP server. For the MCP server use
> `~/.cyberagent/.env` (Option B) or the `env` block in the client config — see
> [MCP Integration](mcp-integration.md#environment-variables-api-keys).

**Option B — a per-user `.env` (recommended for global installs & MCP).** Create
`~/.cyberagent/.env` once; it's loaded no matter where CATS runs from and it
survives `npm install -g` upgrades:

```bash
mkdir -p ~/.cyberagent
cat > ~/.cyberagent/.env <<'EOF'
SHODAN_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
CATS_PLAYBOOKS_DIR=/Users/me/recon/playbooks
CATS_RUNS_DIR=/Users/me/recon/runs
EOF
```

**Option C — a project `.env` (source checkouts).** Copy `.env.example` to `.env`
in the repo root (it is gitignored):

```bash
cp .env.example .env   # then edit
```

### Reference

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
HUNTER_API_KEY=your_key_here             # hunter.emails (no-op without it)
GREYNOISE_API_KEY=your_key_here          # greynoise.ip (no-op without it)
VIRUSTOTAL_API_KEY=your_key_here         # virustotal.lookup (no-op without it)
BINARYEDGE_API_KEY=your_key_here         # binaryedge.host (no-op without it)
INTELX_API_KEY=your_key_here             # intelx.search (no-op without it)
CHROME_PATH=                             # web.screenshot — override Chrome/Chromium path

# ── Paths (great for global installs / MCP) ──
CATS_PLAYBOOKS_DIR=/path/to/my/playbooks # extra .yaml playbooks, merged with built-ins
CATS_RUNS_DIR=/path/to/reports           # where reports go (default: ~/.cyberagent/runs)

# ── Runtime behaviour ──
CATS_TOOL_MODE=full                      # "lean" hides per-executor MCP tools (82 → 22)
CATS_STRICT_PERMISSIONS=0                # "1" makes undeclared env/bin access throw
```

All built-in executors work without keys; the keys above only enable extra
enrichment or integrations.

You can also reference env vars inside a playbook step with `{{env.NAME}}`, e.g.
pass a key explicitly:

```yaml
- name: Shodan Host Data
  uses: shodan.host
  with:
    apiKey: "{{env.SHODAN_API_KEY}}"
```

---

## CLI commands

Beyond the default `run` command, the CLI exposes scale-and-automation commands:

```bash
# Run a playbook (default command — the bare form still works)
node src/index.js -p playbooks/quick-web-recon.yaml --target example.com

# Auto-run every applicable executor (infers domain/IP/CIDR/URL); --passive for safe mode
node src/index.js auto --target example.com [--phase all] [--passive]

# List every executor grouped by phase / posture / domain
node src/index.js capabilities

# Show each extension's declared permissions (network / env / bins)
node src/index.js permissions
# Enforce them: CATS_STRICT_PERMISSIONS=1 makes undeclared env/bin access throw
CATS_STRICT_PERMISSIONS=1 node src/index.js auto --target example.com

# Stateful, agent-style assessment (entity graph + pivot engine + report)
node src/index.js assess start example.com --full        # full assessment in one command
node src/index.js assess start example.com [--passive]   # → id + ranked next actions
node src/index.js assess run <id> --top 5                 # run top suggestions; new pivots surface
node src/index.js assess next <id> [--top 10]             # show ranked next actions
node src/index.js assess report <id> [--json] [--out report.md]
node src/index.js assess list                             # all saved assessments

# Local web dashboard — browse/drive/diff in the browser (localhost-bound)
node src/index.js dashboard [--port 7878]

# Diff two runs — exits non-zero when something changed (handy for monitoring)
node src/index.js diff runs/old.json runs/new.json [--out diff.md]

# Run a batch of targets + playbooks from a YAML watchlist
node src/index.js watch --list watchlists/example.yaml [--out ./runs]

# Run a playbook on a cron schedule (long-running; new findings fire webhooks)
node src/index.js schedule --playbook quick-web-recon --target example.com \
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
