---
id: quick-web-recon
title: Quick Web Reconnaissance
vars:
  target: "example.com"
  scheme: "https"
  timeout: 5000
steps:
  # Fast DNS checks
  - name: DNS A Records
    uses: dns.resolve
    with:
      types: ["A"]
      timeoutMs: 3000

  - name: DNS AAAA Records
    uses: dns.resolve
    with:
      types: ["AAAA"]
      timeoutMs: 3000

  # Basic HTTP analysis
  - name: HTTPS Headers
    uses: http.headers
    with:
      path: "/"
      scheme: "https"
      timeoutMs: "{{vars.timeout}}"

  - name: HTTP Headers (Fallback)
    uses: http.headers
    with:
      path: "/"
      scheme: "http"
      timeoutMs: "{{vars.timeout}}"

  # Essential files
  - name: robots.txt
    uses: http.get
    with:
      path: "/robots.txt"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: sitemap.xml
    uses: http.get
    with:
      path: "/sitemap.xml"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Basic security check
  - name: TLS Certificate
    uses: tls.inspect
    with:
      port: 443
      timeoutMs: 8000

  # Passive subdomain discovery
  - name: Subdomains (crt.sh)
    uses: subdomains.passive
    with:
      sources: ["crtsh"]
      timeoutMs: 10000
---

## Quick Web Reconnaissance for {{vars.target}}

Fast reconnaissance playbook optimized for speed, focusing on essential information gathering without lengthy scans.

### What This Checks

- Basic DNS resolution (A/AAAA records)
- HTTP/HTTPS headers and security
- Essential web files (robots.txt, sitemap.xml)
- TLS certificate information
- Passive subdomain discovery

### Performance Notes

- Optimized timeouts for fast execution
- Skips port scanning for speed
- Focuses on high-value, low-time targets

### Usage

```bash
node ./src/index.js -p ./playbooks/quick-web-recon.md --var target=yourdomain.com
```
