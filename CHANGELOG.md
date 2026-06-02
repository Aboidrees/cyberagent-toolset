# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to a 4-part `MAJOR.MINOR.PATCH.MICRO` version in `package.json`.

## [0.5.0] - 2026-06-02

Phase 2 — Vulnerability intelligence. Seven new executors (six keyless, one
key-gated) and three new playbooks. The MCP server now exposes 23 executor tools
across 12 production playbooks.

### Added

- **`vuln.cve_lookup`** — CVE lookup against the NVD (National Vulnerability
  Database, API v2). Match by CPE, keyword, or product+version; returns CVEs with
  CVSS score, severity, vector, and summary, filtered by `minCvss`. Keyless;
  optional `NVD_API_KEY` raises the rate limit.
- **`shodan.host`** — Shodan host lookup (open ports, services, banners, CVEs,
  tags). Key-gated: runs only when `SHODAN_API_KEY` is set, otherwise a no-op note.
- **`cloud.bucket_finder`** — derives candidate bucket names from the target domain
  and probes AWS S3, GCP Cloud Storage, and Azure Blob for public exposure.
  Read-only, keyless.
- **`http.fuzz_paths`** — active path enumeration with built-in wordlists
  (common/api/admin/php/asp) or a custom list, concurrency-bounded.
- **`http.git_leak`** — exposed `.git/` directory detector; pulls remote-origin and
  last-commit indicators and flags critical on exposure.
- **`http.cors_check`** — CORS misconfiguration probe (origin reflection,
  wildcard-plus-credentials).
- **`http.methods`** — HTTP methods audit via OPTIONS plus active probing of risky
  methods (PUT/DELETE/TRACE/CONNECT/PATCH).
- Three new playbooks: `vulnerability-assessment`, `owasp-top10-recon`, and
  `cloud-security-assessment`.

### Changed

- `all-tools-selftest` now exercises all 23 executors (was 16).
- `_templates.md` gains two new stage sections — VULNERABILITY INTELLIGENCE and
  ESCALATION — with full per-executor documentation.
- Documentation refresh across `README.md`, `docs/executors.md`, `docs/playbooks.md`,
  and `docs/roadmap.md` (Phase 2 items marked complete; 23 checks live).
- Version bumped 0.4.0 → 0.5.0.

### Notes

- Phase 2's report-enhancement sub-item (executive summary, risk matrix,
  CVSS-classified Markdown reports) is not yet implemented.
- `nmap.udp` / `nmap.os` remain available through `nmap.scan` flags (`-sU` / `-O`,
  both root-required) rather than as dedicated executors.

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
