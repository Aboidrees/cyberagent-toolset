# Playbooks

A playbook is a `.yaml` file in `playbooks/` with `id`, `title`, `description`,
optional `vars`, and a list of `steps`. Each step names an executor via `uses:`
and passes options under `with:`. Drop a file in `playbooks/` and it auto-registers
as an MCP tool — no code changes.

## Production playbooks

| Playbook | Focus |
| -------- | ----- |
| `quick-web-recon` | Fast essentials — DNS, HTTP/TLS, subdomains |
| `web-basic-recon` | DNS · WHOIS · ports · HTTP · TLS |
| `web-security-recon` | Exposed files, admin panels, framework leaks |
| `comprehensive-web-recon` | Full infrastructure + web + security sweep |
| `api-cloud-recon` | APIs, microservices, cloud platforms |
| `network-connectivity-test` | Ping + traceroute diagnostics |
| `email-security-assessment` | SPF · DMARC · DKIM · MTA-STS · BIMI |
| `tls-deep-assessment` | Protocols · weak ciphers · chain · OCSP · HSTS |
| `web-headers-assessment` | A–F header grade · WAF/CDN · tech stack |
| `vulnerability-assessment` | CVE lookup · Shodan · bucket finder · git leak |
| `owasp-top10-recon` | Recon mapped to each OWASP Top 10 category |
| `cloud-security-assessment` | Cloud hosting · storage exposure · edge config |

`all-tools-selftest` exercises every executor once.

## Authoring

```bash
cp playbooks/_template.yaml playbooks/my-recon.yaml
```

```yaml
id: my-recon
title: My Recon
description: One-line summary shown as the MCP tool description.
vars:
  target: example.com
  scheme: https
steps:
  - name: DNS Records
    uses: dns.resolve
    with: { types: [A, AAAA, MX, TXT] }
  - name: Headers
    uses: http.headers
    parallel: true          # run concurrently with adjacent parallel steps
    with: { path: "/", scheme: "{{vars.scheme}}" }
```

`{{vars.name}}` and `{{env.NAME}}` are substituted at run time. Available `uses:`
keys are listed in [[Executors]].
