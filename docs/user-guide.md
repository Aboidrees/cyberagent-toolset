# User Guide

A scenario-driven walkthrough of CyberAgentToolSet (CATS). For deep reference see
[Architecture](architecture.md), [Executors](executors.md),
[Playbooks](playbooks.md), [Configuration](configuration.md), and
[MCP Integration](mcp-integration.md).

> ⚠️ **Authorized assessment only.** Active checks (scanning, web, fuzzing, bucket
> probing) send traffic to the target. Only run them against assets you own or are
> explicitly authorized to test. Passive checks never touch the target.

---

## Concepts in 60 seconds

- **Executor** — one capability, addressed by a stable `uses:` key (e.g.
  `dns.resolve`, `http.security_score`).
- **Extension** — a domain module (dns, web, tls, cloud, …) that ships one or more
  executors. Local `extensions/` load out of the box; npm `cyberagent-ext-*`
  packages auto-register.
- **Playbook** — a YAML workflow (`playbooks/*.yaml`) that runs a list of executor
  steps against a target and saves a report.
- **Phase / posture** — every executor is tagged `reconnaissance | scanning |
  gaining-access` and `passive | active`. List everything with the MCP
  `cats_capabilities` tool.

---

## Install

```bash
git clone https://github.com/Aboidrees/cyberagent-toolset.git
cd cyberagent-toolset
npm install
```

Requires Node ≥ 18. `nmap` and `traceroute` are optional (only needed by the
network executors). Full details: [Installation](installation.md).

---

## Scenario 1 — A quick recon

```bash
node src/index.js -p playbooks/quick-web-recon.yaml --target example.com
```

Output goes to `runs/` as JSON + Markdown. The Markdown report opens with an
executive summary + risk matrix. Pick a playbook with [Playbooks](playbooks.md);
common ones:

| Goal | Playbook |
| ---- | -------- |
| Fast first pass | `quick-web-recon` |
| Email auth posture | `email-security-assessment` |
| TLS hardening | `tls-deep-assessment` |
| Security headers + WAF + stack | `web-headers-assessment` |
| Known CVEs + exposure | `vulnerability-assessment` |
| OWASP Top 10 recon | `owasp-top10-recon` |
| Cloud hosting + buckets | `cloud-security-assessment` |
| Exercise every executor | `all-tools-selftest` |

Override variables with `--var`:

```bash
node src/index.js -p playbooks/vulnerability-assessment.yaml \
  --target example.com --var cveKeyword="nginx 1.18.0"
```

---

## Scenario 2 — API keys (Shodan, NVD, AbuseIPDB)

Everything runs keyless. Keys only add enrichment. Copy `.env.example` to `.env`
and fill in what you have — it loads automatically (CLI and MCP, built-in and npm
extensions):

```bash
cp .env.example .env
# edit .env:
SHODAN_API_KEY=...        # enables shodan.host  (paid; account.shodan.io)
NVD_API_KEY=...           # raises vuln.cve_lookup rate limit (free; nvd.nist.gov)
ABUSEIPDB_API_KEY=...     # ip.intel abuse score  (free tier; abuseipdb.com)
```

`.env.example` documents where to get each key and whether it is free or paid. You
can also pass a key per step: `with: { apiKey: "{{env.SHODAN_API_KEY}}" }`.

---

## Scenario 3 — Passive-only (limited authorization)

When you only have OSINT authorization, run a passive playbook (no packets reach
the target): `email-security-assessment` and the recon steps of others are passive.
Check any executor's posture with the MCP `cats_capabilities` tool, or see the
stage tables in [executors.md](executors.md). Active stages are clearly marked in
each playbook with a ⚠ notice.

---

## Scenario 4 — Driving it from Claude (MCP)

Add the server to Claude Desktop (`~/.claude/claude_desktop_config.json`):

```json
{ "mcpServers": { "cyberagent": {
    "command": "node",
    "args": ["/abs/path/to/cyberagent-toolset/src/mcp-server.js"] } } }
```

Then ask Claude to "list capabilities" (`cats_capabilities`), "list recon topics"
(`cats_topics`), or "run the web headers assessment on example.com". Every executor
is also a direct tool (`cats_<uses>`, e.g. `cats_http_security_score`). Full setup:
[MCP Integration](mcp-integration.md).

---

## Scenario 5 — Automation

```bash
# Compare two runs (new ports/subdomains/findings); non-zero exit on change
node src/index.js diff runs/old.json runs/new.json

# Batch many targets × playbooks from a watchlist
node src/index.js watch --list watchlists/example.yaml

# Recurring scan (new findings fire Slack/webhook if configured)
node src/index.js schedule --playbook quick-web-recon --target example.com --cron "0 8 * * 1"

# Export a run to a branded PDF / DOCX / HTML report
node src/index.js report runs/run.json --format pdf --out report.pdf --company "Acme"
```

Configure notifications via `SLACK_WEBHOOK_URL` / `WEBHOOK_URL` +
`NOTIFY_ON_SEVERITY` in `.env`. See [Configuration](configuration.md).

---

## Scenario 6 — Write a custom playbook

Copy the skeleton and edit:

```bash
cp playbooks/_template.yaml playbooks/my-recon.yaml
node src/index.js -p playbooks/my-recon.yaml --target example.com
```

Steps reference executors by `uses:` key; add `parallel: true` to run consecutive
steps concurrently. Full guide: [Creating Playbooks](creating-playbooks.md).

---

## Scenario 7 — Add or install an extension

**Local** — create `extensions/<domain>/index.js` (a descriptor) + `src/*.js`. It
auto-registers. **Installable** — `npm install cyberagent-ext-<name>`; any package
named `cyberagent-ext-*` is discovered automatically. Contract + examples:
[Creating Playbooks → Adding a custom executor](creating-playbooks.md#adding-a-custom-executor-extension)
and [Architecture](architecture.md).

---

## CLI reference

| Command | Purpose |
| ------- | ------- |
| `cyberagent -p <playbook.yaml> --target <host>` | Run a playbook (default) |
| `cyberagent diff <a.json> <b.json>` | Diff two runs |
| `cyberagent watch --list <watchlist.yaml>` | Batch targets × playbooks |
| `cyberagent schedule --playbook <id> --target <host> --cron "<expr>"` | Recurring scan |
| `cyberagent report <run.json> --format pdf\|docx\|html` | Export a report |

(`node src/index.js …` works identically; `cyberagent` is the installed bin name.)

---

## Troubleshooting

Common errors, the security model, and performance tuning are in
[Troubleshooting](troubleshooting.md). Quick checks:

- **No tools in Claude** → confirm the absolute path in the MCP config and that
  `node src/mcp-server.js` prints the startup line.
- **A key-gated executor returns a "skipped" note** → set the key in `.env`.
- **`nmap`/`traceroute` step fails** → install the binary (`brew install nmap`).
