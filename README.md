# MCP Recon Runner

> Modular, playbook-driven reconnaissance tool for cybersecurity professionals.
> Works as a standalone CLI **and** as a live MCP server that gives Claude direct access to all recon capabilities.

> **⚠️ Only test systems you own or have explicit written authorisation to assess. Unauthorised scanning may violate laws and regulations.**

---

## What it does

MCP Recon Runner orchestrates reconnaissance workflows defined in Markdown playbooks. Point it at a target, pick one or more topic-based playbooks, and it runs every check — DNS, WHOIS, port scan, HTTP headers, TLS, subdomain enumeration, and more — then saves structured JSON + Markdown reports.

When the MCP server is running, Claude can drive the entire workflow interactively: list available topics, ask which ones you want, run the selected playbooks, and present findings — all in natural language.

---

## Documentation

| Doc | What it covers |
|-----|----------------|
| [Installation](docs/installation.md) | Prerequisites, platform-specific setup, dependency install |
| [Getting Started](docs/getting-started.md) | First recon in under 5 minutes, output explained |
| [Configuration](docs/configuration.md) | CLI flags, environment variables, output directory |
| [MCP Integration](docs/mcp-integration.md) | MCP server setup, Claude Desktop config, interactive flow |
| [Playbooks](docs/playbooks.md) | Available playbooks, format reference, variable templating |
| [Executors](docs/executors.md) | All 16 executors — options, YAML syntax, return shape |
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
node src/index.js -p playbooks/quick-web-recon.md --target example.com

# 3. Or start the MCP server for Claude
npm run mcp
```

Reports are saved to `runs/` as `.json` and `.md`.

---

## Available playbooks

| Playbook | Steps | Focus |
|----------|-------|-------|
| `quick-web-recon` | 8 | Fast essentials — DNS, headers, TLS, subdomains |
| `web-basic-recon` | 7 | DNS · WHOIS · ports · HTTP · TLS · subdomains |
| `web-security-recon` | 51 | Exposed files, admin panels, framework leaks |
| `comprehensive-web-recon` | 37 | Full infrastructure + web + security sweep |
| `api-cloud-recon` | 39 | REST/GraphQL · cloud · auth · CDN detection |
| `network-connectivity-test` | 2 | Ping + traceroute diagnostics |
| `email-security-assessment` | 3 | SPF · DMARC · DKIM · MTA-STS · BIMI |
| `tls-deep-assessment` | 3 | Protocols · weak ciphers · chain · OCSP · HSTS |
| `web-headers-assessment` | 4 | A–F security header grade · WAF/CDN · tech stack |

---

## Project structure

```
mcp-recon-runner/
├── src/
│   ├── index.js              # CLI entry point
│   ├── mcp-server.js         # MCP server (dynamic tool registration)
│   ├── runner.js             # Playbook orchestration engine
│   ├── executors/            # One file per recon capability
│   │   ├── dns.js            # dns.resolve · dns.reverse
│   │   ├── email.js          # email.security (SPF/DMARC/DKIM/MTA-STS/BIMI)
│   │   ├── http.js           # http.headers/get/security_score/waf_detect/fingerprint
│   │   ├── ip.js             # ip.intel (ASN / IP intelligence)
│   │   ├── nmap.js
│   │   ├── ping.js
│   │   ├── subdomains.js
│   │   ├── tls.js            # tls.inspect · tls.deep
│   │   ├── traceroute.js
│   │   └── whois.js
│   └── utils/
│       ├── fsx.js            # File system helpers
│       ├── logger.js         # stderr-safe step logger
│       ├── os.js             # OS detection + command availability
│       ├── playbooks.js      # Dynamic playbook loader
│       └── validate.js       # Input validation (injection prevention)
├── playbooks/                # Recon playbooks (drop .md here to add tools)
├── docs/                     # Full documentation
└── runs/                     # Auto-generated reports (gitignored)
```

---

## License

MIT — see LICENSE.
Use responsibly. Test ethically. Stay legal.
