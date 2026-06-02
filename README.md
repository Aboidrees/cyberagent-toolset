# MCP Recon Runner

> Modular, playbook-driven reconnaissance tool for cybersecurity professionals.
> Works as a standalone CLI **and** as a live MCP server that gives Claude direct access to all recon capabilities.
> **⚠️ Only test systems you own or have explicit written authorisation to assess. Unauthorised scanning may violate laws and regulations.**

---

## What it does

MCP Recon Runner orchestrates reconnaissance workflows defined in YAML playbooks. Point it at a target, pick one or more topic-based playbooks, and it runs every check — DNS, WHOIS, port scan, HTTP headers, TLS, subdomain enumeration, and more — then saves structured JSON + Markdown reports (and optional PDF/DOCX).

When the MCP server is running, Claude can drive the entire workflow interactively: list available topics, ask which ones you want, run the selected playbooks, and present findings — all in natural language.

---

## Documentation

| Doc | What it covers |
| ----- | ---------------- |
| [Installation](docs/installation.md) | Prerequisites, platform-specific setup, dependency install |
| [Getting Started](docs/getting-started.md) | First recon in under 5 minutes, output explained |
| [Configuration](docs/configuration.md) | CLI flags, environment variables, output directory |
| [MCP Integration](docs/mcp-integration.md) | MCP server setup, Claude Desktop config, interactive flow |
| [Playbooks](docs/playbooks.md) | Available playbooks, format reference, variable templating |
| [Executors](docs/executors.md) | All 23 executors — options, YAML syntax, return shape |
| [Creating Playbooks](docs/creating-playbooks.md) | Step-by-step guide to writing custom playbooks |
| [Troubleshooting](docs/troubleshooting.md) | Common errors, debug tips, performance tuning |
| [Roadmap](docs/roadmap.md) | Planned executors, features, playbooks, and integrations |

---

## Quick start

```bash
# 1. Clone and install
git clone https://github.com/yourusername/mcp-recon-runner.git
cd mcp-recon-runner
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
mcp-recon-runner/
├── src/
│   ├── index.js              # CLI entry (run · diff · watch · schedule · report)
│   ├── mcp-server.js         # MCP server (dynamic tool registration)
│   ├── runner.js             # Playbook engine (parallel steps, findings rollup)
│   ├── diff.js               # Compare two runs
│   ├── watch.js              # Run a watchlist of targets
│   ├── schedule.js           # Cron-scheduled scanning (node-cron)
│   ├── report.js             # PDF / DOCX / HTML report export
│   ├── executors/            # One file per recon capability
│   │   ├── cloud.js          # cloud.bucket_finder (AWS/GCP/Azure)
│   │   ├── dns.js            # dns.resolve · dns.reverse
│   │   ├── email.js          # email.security (SPF/DMARC/DKIM/MTA-STS/BIMI)
│   │   ├── http.js           # headers/get/security_score/waf_detect/fingerprint/cors_check/methods/fuzz_paths/git_leak
│   │   ├── ip.js             # ip.intel (ASN / IP intelligence)
│   │   ├── nmap.js
│   │   ├── ping.js
│   │   ├── shodan.js         # shodan.host (key-gated)
│   │   ├── subdomains.js
│   │   ├── tls.js            # tls.inspect · tls.deep
│   │   ├── traceroute.js
│   │   ├── vuln.js           # vuln.cve_lookup (NVD)
│   │   └── whois.js
│   └── utils/
│       ├── findings.js       # Severity-rated findings model
│       ├── fsx.js            # File system helpers
│       ├── notify.js         # Webhook / Slack notifications
│       ├── logger.js         # stderr-safe step logger
│       ├── os.js             # OS detection + command availability
│       ├── playbooks.js      # Dynamic playbook loader
│       └── validate.js       # Input validation (injection prevention)
├── playbooks/                # Recon playbooks (drop .yaml here to add tools)
├── docs/                     # Full documentation
└── runs/                     # Auto-generated reports (gitignored)
```

---

## License

MIT — see LICENSE.
Use responsibly. Test ethically. Stay legal.
