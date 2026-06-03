# CyberAgentToolSet (CATS)

> * An MCP server + CLI that orchestrates authorized security assessments across the attack lifecycle (reconnaissance · scanning · gaining-access) via installable extensions.
> * Works as a standalone CLI **and** as a live MCP server that gives Claude direct access to every capability.
> * **⚠️ Only test systems you own or have explicit written authorisation to assess. Unauthorised scanning may violate laws and regulations.**

---

## What it does

CyberAgentToolSet (CATS) orchestrates reconnaissance workflows defined in YAML playbooks. Point it at a target, pick one or more topic-based playbooks, and it runs every check — DNS, WHOIS, port scan, HTTP headers, TLS, subdomain enumeration, and more — then saves structured JSON + Markdown reports (and optional PDF/DOCX).

When the MCP server is running, Claude can drive the entire workflow interactively: list available topics, ask which ones you want, run the selected playbooks, and present findings — all in natural language.

---

## Documentation

| Doc | What it covers |
| ----- | ---------------- |
| [Installation](docs/installation.md) | Prerequisites, platform-specific setup, dependency install |
| [Getting Started](docs/getting-started.md) | First recon in under 5 minutes, output explained |
| [User Guide](docs/user-guide.md) | Scenario-driven walkthrough of every use case |
| [Configuration](docs/configuration.md) | CLI flags, environment variables, output directory |
| [MCP Integration](docs/mcp-integration.md) | MCP server setup, Claude Desktop config, interactive flow |
| [Playbooks](docs/playbooks.md) | Available playbooks, format reference, variable templating |
| [Executors](docs/executors.md) | All 60 executors — options, YAML syntax, return shape |
| [Architecture](docs/architecture.md) | Extension model, catalog, taxonomy, plugin contract |
| [Creating Playbooks](docs/creating-playbooks.md) | Step-by-step guide to writing custom playbooks |
| [Troubleshooting](docs/troubleshooting.md) | Common errors, debug tips, performance tuning |
| [Roadmap](docs/roadmap.md) | Planned executors, features, playbooks, and integrations |

---

## Quick start

```bash
# 1. Clone and install
git clone https://github.com/yourusername/cyberagent-toolset.git
cd cyberagent-toolset
npm install

# 2. Run a quick recon
node src/index.js -p playbooks/quick-web-recon.yaml --target example.com

# 3. Or start the MCP server for Claude
npm run mcp
```

Reports are saved to `runs/` as `.json` and `.md`.

---

## Automation (CLI)

```bash
# Auto-run every applicable executor (no playbook); --passive for OSINT-only scope
node src/index.js auto --target cyberany.org

# List capabilities by phase / posture / domain
node src/index.js capabilities

# Diff two runs (exits non-zero when something changed)
node src/index.js diff runs/old.json runs/new.json

# Batch-run a watchlist of targets + playbooks
node src/index.js watch --list watchlists/example.yaml

# Schedule a recurring scan (new findings fire webhooks)
node src/index.js schedule --playbook quick-web-recon --target fortmind.qa --cron "0 8 * * 1"

# Export a run to PDF / DOCX / HTML
node src/index.js report runs/run.json --format pdf --out report.pdf
```

Parallel steps (`parallel: true`), an executive-summary + risk-matrix in every
report, and Slack/webhook notifications (`SLACK_WEBHOOK_URL` / `WEBHOOK_URL`) are
built in. See [Configuration](docs/configuration.md).

---

## Agent-driven assessments

Beyond one-shot playbooks, CATS runs **stateful assessments** — the way an AI
agent (or you) drives a full investigation. Each result feeds an **entity graph**
(subdomains, IPs, ports, URLs, CVEs…) and a **pivot engine** that suggests the
next best actions: a discovered subdomain queues a web/TLS sweep, an open `445`
queues `smb.probe`, an unscored CVE queues `vuln.epss`. The final report
correlates findings (CVE × EPSS exploit-probability) into a prioritized list.

```bash
node src/index.js assess start example.com          # → assessment id + ranked next steps
node src/index.js assess run  <id> --top 5           # run the top suggestions; new pivots surface
node src/index.js assess next <id>                   # see the updated ranked actions
node src/index.js assess report <id>                 # prioritized, correlated report
```

Over MCP the same loop is `cats_assess_start → cats_assess_run → cats_assess_next
→ cats_assess_report`, so Claude can conduct and reason about the whole
assessment conversationally.

---

## Available playbooks

| Playbook | Steps | Focus |
| ---------- | ------- | ------- |
| `quick-web-recon` | 8 | Fast essentials — DNS, headers, TLS, subdomains |
| `web-basic-recon` | 7 | DNS · WHOIS · ports · HTTP · TLS · subdomains |
| `web-security-recon` | 51 | Exposed files, admin panels, framework leaks |
| `comprehensive-web-recon` | 37 | Full infrastructure + web + security sweep |
| `api-cloud-recon` | 39 | REST/GraphQL · cloud · auth · CDN detection |
| `network-connectivity-test` | 2 | Ping + traceroute diagnostics |
| `email-security-assessment` | 3 | SPF · DMARC · DKIM · MTA-STS · BIMI |
| `tls-deep-assessment` | 3 | Protocols · weak ciphers · chain · OCSP · HSTS |
| `web-headers-assessment` | 4 | A–F security header grade · WAF/CDN · tech stack |
| `vulnerability-assessment` | 8 | CVE lookup · Shodan · bucket finder · git leak |
| `owasp-top10-recon` | 14 | Recon mapped to each OWASP Top 10 category |
| `cloud-security-assessment` | 11 | Cloud hosting · storage exposure · edge config |

---

## Project structure

```TREE
cyberagent-toolset/
├── src/
│   ├── index.js              # CLI entry (run · diff · watch · schedule · report)
│   ├── mcp-server.js         # MCP server (catalog-driven tool registration)
│   ├── runner.js             # Playbook engine (parallel steps, findings rollup)
│   ├── sdk.js                # #sdk — shared services extensions build against
│   ├── diff.js · watch.js · schedule.js · report.js
│   ├── extensions/
│   │   └── loader.js         # Discover extensions → build the catalog
│   └── utils/                # findings · fsx · notify · logger · os · playbooks · validate
├── extensions/               # Domain modules (each = one installable extension)
│   ├── dns/ whois/ rdap/ email/ ip-intel/ threat-intel/ securitytrails/ censys/ github-leaks/ hunter/   # recon
│   ├── network/ web/ tls/ ssh/ smb/ snmp/ mysql/ postgres/ rdp/ ldap/ nuclei/   # scanning
│   ├── cloud/                                             # gaining-access
│   └── <domain>/
│       ├── index.js          # Extension Descriptor (manifest: executors + metadata)
│       ├── src/*.js          # capability implementations
│       └── report.js         # owns this domain's findings extraction
├── playbooks/                # YAML playbooks (drop .yaml here to add tools)
├── watchlists/               # Target watchlists for `watch`
├── schemas/                  # JSON Schemas for playbooks/watchlists
├── docs/                     # Full documentation (see architecture.md)
└── runs/                     # Auto-generated reports (gitignored)
```

Third-party extensions install as npm packages named `cyberagent-ext-*` and
auto-register — see [Architecture](docs/architecture.md).

---

## License

MIT — see LICENSE.
Use responsibly. Test ethically. Stay legal.
