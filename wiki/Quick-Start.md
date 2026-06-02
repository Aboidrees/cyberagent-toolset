# Quick Start

## 1. Run a playbook

```bash
node src/index.js -p playbooks/quick-web-recon.yaml --target example.com
```

Reports are written to `runs/` as JSON + Markdown. The Markdown opens with an
executive summary and a risk matrix.

## 2. Pick the right playbook

| Goal | Playbook |
| ---- | -------- |
| Fast first pass | `quick-web-recon` |
| Email auth (SPF/DMARC/DKIM/MTA-STS/BIMI) | `email-security-assessment` |
| TLS hardening | `tls-deep-assessment` |
| Security headers + WAF + tech stack | `web-headers-assessment` |
| Known CVEs + exposure | `vulnerability-assessment` |
| OWASP Top 10 recon | `owasp-top10-recon` |
| Cloud hosting + public buckets | `cloud-security-assessment` |
| Standard baseline (DNS/WHOIS/ports/HTTP/TLS) | `web-basic-recon` |
| Exercise every executor | `all-tools-selftest` |

See [[Playbooks]] for the full list.

## 3. Override variables

```bash
node src/index.js -p playbooks/vulnerability-assessment.yaml \
  --target example.com --var cveKeyword="nginx 1.18.0"
```

## 4. Export a report

```bash
node src/index.js report runs/<the-run>.json --format pdf --out report.pdf
```

## 5. Drive it from Claude

Add the MCP server to Claude Desktop and ask it to run topics — see
[[MCP Integration]].

Next: [[User Guide]] walks through every scenario.
