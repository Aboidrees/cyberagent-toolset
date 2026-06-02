---
id: web-headers-assessment
title: Web Headers Assessment
vars:
  target: "example.com"
  scheme: "https"
  timeout: 10000
steps:
  # A–F security header grade
  - name: Security Header Score
    uses: http.security_score
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # WAF / CDN in front of the app changes how findings are interpreted
  - name: WAF / CDN Fingerprint
    uses: http.waf_detect
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Technology stack behind the headers
  - name: Technology Fingerprint
    uses: http.fingerprint
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      deep: true
      timeoutMs: "{{vars.timeout}}"

  # Raw headers for manual review
  - name: Raw Response Headers
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
---

## Web Headers Assessment for {{vars.target}}

A focused look at what the HTTP response headers say about a site's security
hardening, edge infrastructure, and technology stack.

### What This Checks

- **Security header grade (A–F)** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, and the Cross-Origin-* family, each weighted,
  with per-header remediation advice and version-banner info-leak detection
- **WAF / CDN fingerprint** — Cloudflare, AWS WAF/CloudFront, Akamai, Imperva, Sucuri,
  F5 BIG-IP, Fastly, Varnish, Azure Front Door
- **Technology fingerprint** — server, language, framework, CMS, analytics, JS libraries

### Reading the Grade

The score is the percentage of weighted header points present. An **A** means the
core protections (CSP + HSTS + framing/MIME) are all in place; an **F** means the
response ships with essentially no security headers.

### Usage

```bash
node ./src/index.js -p ./playbooks/web-headers-assessment.md --var target=yourdomain.com
```
