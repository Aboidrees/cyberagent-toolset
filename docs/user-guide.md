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
- **Playbook** — a *fixed* YAML workflow (`playbooks/*.yaml`) that runs a set list
  of executor steps against a target and saves a report.
- **Assessment** — a *dynamic*, stateful investigation: it discovers entities and
  pivots onto them (subdomain → web sweep, open port → service probe, CVE → EPSS),
  then synthesizes a prioritized report. Run with `assess start <t> --full`. Both
  playbooks and assessments are first-class — pick the one that fits.
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

## Scenario 1b — Auto (no playbook needed)

Point it at a target and it runs every applicable executor (inferring domain / IP /
CIDR / URL):

```bash
node src/index.js auto --target example.com                 # all applicable reconnaissance
node src/index.js auto --target 192.0.2.0/24 --phase all     # everything applicable to a CIDR
node src/index.js auto --target example.com --passive        # passive-only
```

List what is available with `cyberagent capabilities` (grouped by phase / posture /
domain).

---

## Scenario 1c — A full assessment (the agent-driven way)

An **assessment** is the smart alternative to a fixed playbook: it discovers
entities (subdomains, IPs, ports, URLs, CVEs) and *pivots* onto them — a found
subdomain triggers a web/TLS sweep on it, an open `445` triggers `smb.probe`, a
discovered CVE triggers `vuln.epss`. `--full` drives the whole loop in one command.

```bash
node src/index.js assess start example.com --full           # full active assessment → report
node src/index.js assess start example.com --full --passive # OSINT-only (no packets to the host)
```

Step through it manually instead, if you prefer:

```bash
node src/index.js assess start example.com        # → assessment id + ranked next actions
node src/index.js assess run  <id> --top 5        # run the top suggestions; new pivots surface
node src/index.js assess next <id>                # see the updated ranked actions
node src/index.js assess report <id>              # prioritized report (top risks, entities, coverage)
```

The report correlates findings (CVE × EPSS exploit-probability). Export and diff it
like a run:

```bash
node src/index.js assess report <id> --format pdf --out report.pdf --company "Acme"
node src/index.js assess diff <idA> <idB>         # compare a target over time (exits non-zero on change)
```

**Assessment vs run:** a *run* executes a fixed playbook; an *assessment* decides
what to run next from what it finds. Both produce reports you can export and diff —
keep whichever fits the job.

---

## Scenario 1d — The web dashboard

A local browser UI to browse assessments and runs, drive an assessment, and diff
runs. Localhost-bound (it can trigger active scans), no extra dependency:

```bash
node src/index.js dashboard            # → http://127.0.0.1:7878
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

## Scenario 2b — Nuclei (thousands of templated checks)

`nuclei.scan` wraps the Nuclei engine. Install the binary, then it runs as part of
any playbook (or directly via the MCP `cats_nuclei_scan` tool):

```bash
brew install nuclei
node src/index.js -p playbooks/vulnerability-assessment.yaml --target example.com
```

Without the binary it is a no-op note, so it never breaks a run.

---

## Scenario 3 — Passive-only (limited authorization)

When you only have OSINT authorization, add `--passive` to any run — it skips every
active executor (no packets reach the target host):

```bash
node src/index.js -p playbooks/web-headers-assessment.yaml --target example.com --passive
node src/index.js auto --target example.com --passive
```

Skipped steps are marked `⏭️ Skipped` in the report. Check any executors posture
with `cyberagent capabilities` (or the MCP `cats_capabilities` tool).

---

## Scenario 4 — Driving it from Claude (MCP)

Add the server to Claude Desktop (`~/.claude/claude_desktop_config.json`):

```json
{ "mcpServers": { "cyberagent": {
    "command": "node",
    "args": ["/abs/path/to/cyberagent-toolset/src/mcp-server.js"] } } }
```

Then ask Claude to "list capabilities" (`cats_capabilities`), "list recon topics"
(`cats_topics`), or **"assess example.com"** — Claude drives the stateful loop via
`cats_assess_start → cats_assess_run → cats_assess_report` (or use the one-click
`assess-domain` prompt). Every executor is also a direct tool (`cats_<uses>`, e.g.
`cats_http_security_score`). Full setup:
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
| `cyberagent auto --target <host>` | Auto-run every applicable executor |
| `cyberagent assess start <host> --full` | Full pivot-driven assessment → report |
| `cyberagent assess report <id> --format pdf` | Export an assessment (pdf/docx/html) |
| `cyberagent assess diff <idA> <idB>` | Compare a target's assessments over time |
| `cyberagent dashboard` | Local web UI (browse / drive / diff) |
| `cyberagent capabilities` | List executors by phase / posture / domain |
| `cyberagent permissions` | Show each extension's declared permissions |
| `cyberagent diff <a.json> <b.json>` | Diff two runs |
| `cyberagent watch --list <watchlist.yaml>` | Batch targets × playbooks |
| `cyberagent schedule --playbook <id> --target <host> --cron "<expr>"` | Recurring scan |
| `cyberagent report <run.json> --format pdf\|docx\|html` | Export a run report |

(`node src/index.js …` works identically; `cyberagent` is the installed bin name.)

---

## Troubleshooting

Common errors, the security model, and performance tuning are in
[Troubleshooting](troubleshooting.md). Quick checks:

- **No tools in Claude** → confirm the absolute path in the MCP config and that
  `node src/mcp-server.js` prints the startup line.
- **A key-gated executor returns a "skipped" note** → set the key in `.env`.
- **`nmap`/`traceroute` step fails** → install the binary (`brew install nmap`).
