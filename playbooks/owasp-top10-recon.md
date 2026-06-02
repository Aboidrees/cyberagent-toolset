---
id: owasp-top10-recon
title: OWASP Top 10 Reconnaissance
vars:
  target: "example.com"
  scheme: "https"
  timeout: 10000
steps:
  # A01 — Broken Access Control: look for admin/management surfaces
  - name: "A01 Access Control — admin surface"
    uses: http.fuzz_paths
    with:
      wordlist: "admin"
      scheme: "{{vars.scheme}}"
      timeoutMs: 20000        # step budget (per-request bounded internally)

  # A02 — Cryptographic Failures: protocol/cipher/cert weaknesses
  - name: "A02 Cryptographic Failures — deep TLS"
    uses: tls.deep
    with:
      port: 443
      timeoutMs: 10000

  # A03 — Injection (recon): surface API/GraphQL endpoints to test later
  - name: "A03 Injection — API surface"
    uses: http.fuzz_paths
    with:
      wordlist: "api"
      scheme: "{{vars.scheme}}"
      timeoutMs: 20000        # step budget (per-request bounded internally)

  # A04 — Insecure Design (recon): fingerprint the stack
  - name: "A04 Insecure Design — tech fingerprint"
    uses: http.fingerprint
    with:
      path: "/"
      deep: true
      timeoutMs: "{{vars.timeout}}"

  # A05 — Security Misconfiguration: header grade + exposed config
  - name: "A05 Misconfiguration — header score"
    uses: http.security_score
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: "A05 Misconfiguration — common exposures"
    uses: http.fuzz_paths
    with:
      wordlist: "common"
      scheme: "{{vars.scheme}}"
      timeoutMs: 20000        # step budget (per-request bounded internally)

  # A06 — Vulnerable & Outdated Components: CVE lookup (override keyword)
  - name: "A06 Vulnerable Components — CVE lookup"
    uses: vuln.cve_lookup
    with:
      keyword: "{{vars.target}}"
      minCvss: 7.0
      maxResults: 10

  # A07 — Identification & Authentication Failures: login surfaces
  - name: "A07 Auth Failures — login surface"
    uses: http.fuzz_paths
    with:
      wordlist: "php"
      scheme: "{{vars.scheme}}"
      timeoutMs: 20000        # step budget (per-request bounded internally)

  # A08 — Software & Data Integrity Failures: exposed VCS
  - name: "A08 Integrity Failures — git leak"
    uses: http.git_leak
    with:
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # A08 — also check email-supply-chain trust (DMARC/DKIM/SPF)
  - name: "A08 Integrity — email auth"
    uses: email.security
    with:
      timeoutMs: 20000

  # A09 — Security Logging & Monitoring (recon): WAF/CDN presence
  - name: "A09 Logging & Monitoring — WAF/CDN"
    uses: http.waf_detect
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # A10 — SSRF (recon): map infrastructure / hosting for SSRF surface
  - name: "A10 SSRF — IP / hosting intel"
    uses: ip.intel

  - name: "A10 SSRF — DNS records"
    uses: dns.resolve
    with:
      types: ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]
      timeoutMs: 8000
---

## OWASP Top 10 Reconnaissance for {{vars.target}}

Maps the **recon phase** of each OWASP Top 10 (2021) category to the executors
that gather the relevant signal. This is reconnaissance, not exploitation — it
surfaces where to look, not proof of a vulnerability.

### Category Coverage

| OWASP | Category | Recon performed |
| ----- | -------- | --------------- |
| A01 | Broken Access Control | Admin/management surface enumeration |
| A02 | Cryptographic Failures | Deep TLS (protocols, ciphers, chain) |
| A03 | Injection | API/GraphQL endpoint surface |
| A04 | Insecure Design | Technology stack fingerprint |
| A05 | Security Misconfiguration | Header grade + common exposures |
| A06 | Vulnerable Components | NVD CVE lookup |
| A07 | Auth Failures | Login/auth surface enumeration |
| A08 | Integrity Failures | Exposed `.git` + email auth |
| A09 | Logging & Monitoring | WAF/CDN presence |
| A10 | SSRF | IP/hosting + DNS infrastructure map |

### Notes

- A06's CVE lookup defaults to the target name as the keyword — override with the
  actual product/version you discovered (e.g. `--var target="Apache 2.4.49"` is not
  ideal; prefer running `vuln.cve_lookup` directly with a real product keyword).
- A03/A10 recon surfaces endpoints/infrastructure; actual injection/SSRF testing is
  out of scope for a recon tool.

⚠️ Includes active steps (path fuzzing). Run only against authorized targets.

### Usage

```bash
node ./src/index.js -p ./playbooks/owasp-top10-recon.md --var target=authorized-target.com
```
