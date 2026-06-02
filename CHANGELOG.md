# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to a 4-part `MAJOR.MINOR.PATCH.MICRO` version in `package.json`.

## [0.4.0] - 2026-06-02

Phase 1 — Deeper intelligence. Seven new recon executors (all keyless), three new
playbooks, and a documentation refresh. The MCP server now exposes 16 executor
tools (up from 8).

### Added

- **`dns.reverse`** — reverse DNS / PTR lookup and sweep. Accepts a single IP, an
  IPv4 CIDR range (concurrent sweep, capped at 256 hosts), or a hostname (resolves
  then reverses). Each lookup is individually time-bounded.
- **`email.security`** — email authentication posture: SPF, DMARC, DKIM (probes
  common selectors), MTA-STS, and BIMI, with severity-rated findings. Passive DNS
  plus one HTTPS fetch for the MTA-STS policy. All lookups run concurrently and are
  individually capped. No API key.
- **`ip.intel`** — ASN / IP intelligence via Team Cymru's keyless DNS service: ASN,
  BGP prefix, country, registry, and hosting/CDN classification. Optional AbuseIPDB
  abuse-reputation enrichment, enabled only when `ABUSEIPDB_API_KEY` is set.
- **`http.security_score`** — A–F grade of security response headers (CSP, HSTS,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
  Cross-Origin-*) with per-header remediation advice and info-leak detection.
- **`http.waf_detect`** — WAF/CDN fingerprint from headers, cookies, and banners.
  Detects Cloudflare, AWS WAF/CloudFront, Akamai, Imperva/Incapsula, Sucuri, F5
  BIG-IP, Fastly, Varnish, Azure Front Door, Barracuda, and Wordfence.
- **`http.fingerprint`** — technology stack fingerprint from headers and HTML body:
  server, language, framework, CMS, analytics, and JS libraries.
- **`tls.deep`** — vulnerability-oriented TLS analysis: protocol support matrix
  (flags TLS 1.0/1.1), weak-cipher probes (RC4/3DES/NULL), certificate chain
  validation, OCSP stapling, and HSTS/preload status.
- Three new playbooks: `email-security-assessment`, `tls-deep-assessment`, and
  `web-headers-assessment`.

### Changed

- `all-tools-selftest` now exercises all 16 executors (was 9).
- `_templates.md` reorganized into stage-segmented sections (PASSIVE/OSINT,
  LIVENESS, PORTSCAN, WEBSCANNER) with full per-executor option documentation.
- Documentation refresh across `README.md`, `docs/executors.md`, `docs/playbooks.md`,
  and `docs/roadmap.md` (Phase 1 items marked complete; 16 checks live).
- Version bumped 0.3.0 → 0.4.0.

### Security

- `http.*` URL building now whitelists the scheme to http/https and rejects paths
  containing credentials (`@`), whitespace, control characters, backslashes, or a
  protocol-relative (`//`) prefix — closing a host-override/SSRF vector on the
  caller-supplied `scheme`/`path` options.
- `ip.intel` validates the ASN parsed from the Team Cymru DNS response is numeric
  before interpolating it into a follow-up DNS query.
- All HTTP GETs now cap response body size (`maxContentLength`) to prevent memory
  exhaustion from a hostile target.
