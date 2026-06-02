---
id: tls-deep-assessment
title: TLS Deep Assessment
vars:
  target: "example.com"
  port: 443
steps:
  # Baseline certificate metadata
  - name: Certificate Overview
    uses: tls.inspect
    with:
      port: "{{vars.port}}"
      timeoutMs: 12000

  # Vulnerability-oriented deep analysis
  - name: Deep TLS Analysis
    uses: tls.deep
    with:
      port: "{{vars.port}}"
      timeoutMs: 10000

  # Confirm HSTS is also advertised over HTTP responses
  - name: HSTS Header (HTTP layer)
    uses: http.headers
    with:
      path: "/"
      scheme: "https"
      timeoutMs: 10000
---

## TLS Deep Assessment for {{vars.target}}

Goes beyond certificate metadata to evaluate the *security* of the TLS
configuration — the things that get a server flagged in a compliance scan.

### What This Checks

- **Protocol support matrix** — flags deprecated TLS 1.0 / 1.1 if still enabled
- **Weak cipher negotiation** — probes for RC4, 3DES, and NULL cipher families
- **Certificate chain validation** — reports untrusted roots / incomplete chains
- **OCSP stapling** — whether the server staples revocation responses
- **HSTS & preload** — header presence, `max-age`, `includeSubDomains`, preload eligibility

### How It Works

`tls.deep` opens a series of short, independent TLS handshakes — one per protocol
version and one per weak-cipher family — and records which ones negotiate. A
successful handshake with a deprecated protocol or weak cipher is a finding, not
a success. No data is ever transmitted over these probe connections.

### Usage

```bash
node ./src/index.js -p ./playbooks/tls-deep-assessment.md --var target=yourdomain.com
```
