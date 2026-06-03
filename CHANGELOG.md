# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to a 4-part `MAJOR.MINOR.PATCH.MICRO` version in `package.json`.

## [0.10.0] - 2026-06-03

Phase 6 — tool expansion. Three keyless executors (43 total across 13 extensions).

### Added

- **`vuln.epss`** (threat-intel, recon · passive, keyless) — EPSS exploit-probability
  scoring from FIRST.org for one or more CVEs. Pairs with `vuln.cve_lookup` to
  prioritise by real-world exploitation likelihood, not just CVSS. Flags CVEs above
  `findingThreshold` (default 0.5; `high` at ≥0.9).
- **`http.graphql`** (web, scanning · active) — probes common GraphQL paths
  (`/graphql`, `/api/graphql`, `/v1/graphql`, …) and flags endpoints exposing schema
  introspection.
- **`dns.txt_fingerprint`** (dns, recon · passive) — fingerprints the SaaS/vendor
  footprint from TXT domain-verification tokens (Google, Microsoft 365, Atlassian,
  Stripe, DocuSign, …). Uses DNS-over-HTTPS with a system-resolver fallback.

### Changed

- Self-test playbook now exercises 43/43 executors; schema `uses`-enum regenerated.

## [0.9.0] - 2026-06-03

Phase 5 — hardening + capability unlocks. Adds CI, a license, passive-only safe
mode, target-aware auto-assembly, and phase-grouped listing/reports.

### Added

- **Passive-only / safe mode** — `--passive` (CLI `run` and `auto`; MCP `cats_run`
  / `cats_run_multi` / `cats_play__`) skips any active executor via per-executor
  posture metadata. Skipped steps render as `⏭️ Skipped` in the report.
- **Target-aware auto-assembly** — `cyberagent auto --target <x>` infers the target
  type (domain/ip/cidr/url) and runs every applicable executor with no playbook.
  Flags: `--phase reconnaissance|scanning|gaining-access|all`, `--passive`.
- **`capabilities` / `list` command** — prints every executor grouped by phase /
  posture / domain (`--json` for raw); mirrors the MCP `cats_capabilities` tool.
- **Phase-grouped reports** — each step + finding is annotated with phase/posture/
  domain; the executive summary gains a "Coverage by phase" line and findings are
  grouped under "Findings by phase".
- **CI** (`.github/workflows/ci.yml`) — a `validate` gate (`node --check` +
  `scripts/ci-validate.mjs` invariants + MCP boot) and a `selftest` smoke job
  (runs the 40-step self-test against example.com, asserts every step executed).
- **`LICENSE`** — MIT, matching the README.
- **`scripts/ci-validate.mjs`** — deterministic invariants (catalog, playbook/
  watchlist resolution, schema uses-enum sync), usable locally too.

### Changed

- `runPlaybook` accepts an in-memory `playbook` object (used by `auto`) and a
  `posture` option. Version bumped 0.8.0 → 0.9.0.

## [0.8.0] - 2026-06-02

Phase 4 — tool expansion. **23 → 40 executors** across **13 extensions**, plus the
Nuclei multiplier (thousands of templated checks). MCP now exposes 57 tools.

### Added for 0.8.0

- **Keyless executor batch (+12):**
  - DNS: `dns.dnssec` (DoH), `dns.caa`, `subdomains.bruteforce`.
  - Web: `http.cookies`, `http.robots`, `http.secrets`, `http.open_redirect`,
    `http.subdomain_takeover`, `web.wayback` (passive archive URLs).
  - Network: `nmap.udp`, `nmap.os` (no-op note without root), `network.banner`.
- **`nuclei.scan`** — wraps the nuclei binary (CVEs, exposures, misconfigs,
  takeovers); no-op note when the binary is absent.
- **Key-gated intel extensions** (no-op without their key, like Shodan):
  `securitytrails.subdomains`, `securitytrails.dns_history`, `censys.host`,
  `github.leaks`.
- `.env.example` documents the new keys (SecurityTrails, Censys, GitHub token).

### Changed for 0.8.0

- `all-tools-selftest` now exercises all 40 executors (passes 40/40).
- Multi-request executors (`network.banner`) decouple per-request timeout from the
  step budget; `nmap.udp`/`nmap.os` no-op gracefully when root is required.
- Docs: executors.md gains the expanded toolset; roadmap marks nmap UDP/OS,
  SecurityTrails, and Nuclei complete; version bumped 0.7.0 → 0.8.0.

## [0.7.0] - 2026-06-02

**Renamed to CyberAgentToolSet (CATS)** and re-architected around installable
**extensions**. Capabilities are now domain modules classified by attack-lifecycle
phase; the core is an engine + catalog that discovers them (locally and from npm
plugins). No new executors — the 23 are re-homed, and the 23-executor self-test
stays green.

### Changed for 0.7.0

- **Project renamed** `mcp-recon-runner` → `cyberagent-toolset`. Bins are now
  `cyberagent` (CLI) and `cyberagent-mcp` (server); the MCP tool prefix is `cats_`.
- **Extension architecture.** Executors moved from `src/executors/*.js` into
  domain extensions under `extensions/<domain>/` (dns, whois, email, ip-intel,
  threat-intel, network, web, tls, cloud). Each extension ships a descriptor
  (manifest) declaring its executors with `phase` / `posture` / `targetTypes` /
  `permissions`, and owns its findings extraction (`report.js`).
- **Catalog-driven core.** `src/extensions/loader.js` discovers extensions and
  builds the registry; `runner.js` and `mcp-server.js` no longer hardcode
  executors. The MCP server generates one `cats_<uses>` tool per executor plus a
  new `cats_capabilities` tool that lists everything by phase/posture/domain.
- **`uses:` keys unchanged** — playbooks and the 23-executor self-test are
  untouched by the move.
- `utils/findings.js` is now a thin aggregator; per-executor severity logic lives
  in each extension's `report.js`.
- `docs/architecture.md` documents the model; version bumped 0.6.0 → 0.7.0.

### Added for 0.7.0

- **Installable extensions, day one.** Local `extensions/` load out of the box;
  npm packages named `cyberagent-ext-*` / `@cyberagent/ext-*` auto-register via the
  same descriptor contract. Shared services (`validateTarget`, …) are exposed as
  `#sdk` for local extensions and injected as `ctx` into every `run()` for plugins.
- Attack-lifecycle taxonomy: phases `reconnaissance` · `scanning` · `gaining-access`
  (with `maintaining-access` / `covering-tracks` as out-of-scope vocabulary only).

## [0.6.1] - 2026-06-02

Phase 3 — Scale and automation. Parallel execution, scheduling, diffing, batch
watchlists, professional report export, and webhook notifications. The CLI is now
multi-command (`run` · `diff` · `watch` · `schedule` · `report`).

### Added for 0.6.1

- **Parallel step execution** — steps flagged `parallel: true` run concurrently in
  batches; a non-parallel step is a barrier. Output order is preserved.
- **Scheduled scanning** — `schedule --playbook X --target Y --cron "0 8 * * 1"`
  runs a playbook on a cron schedule (via `node-cron`); new findings flow through
  the webhook path for monitoring.
- **Diff reports** — `diff a.json b.json` highlights new/removed open ports,
  subdomains, DNS records, certificate changes, and security findings. Exits
  non-zero when something changed.
- **Target watchlist** — `watch --list watchlist.yml` batch-runs many targets ×
  playbooks in one command.
- **Report export** — `report run.json --format pdf|docx|html` generates a branded
  assessment report with executive summary, risk matrix, and findings table (via
  `pdfkit` / `docx`).
- **Webhook / notifications** — Slack (`SLACK_WEBHOOK_URL`) and generic
  (`WEBHOOK_URL`) notifications on completion, gated by `NOTIFY_ON_SEVERITY`.
- **Report enhancement** (the deferred Phase 2 item) — every run now carries an
  aggregated, severity-rated findings rollup with an executive summary and risk
  matrix at the top of the Markdown report.

### Changed for 0.6.0

- CLI restructured into subcommands; the bare `-p <playbook> --target <host>` form
  is preserved as the default command.
- **Playbooks are now `.yaml` files** (pure YAML with id/title/description) instead
  of `.md`. Legacy `.md` still loads for backward compatibility; `playbooks/_template.yaml`
  is the new skeleton.
- Watchlists live in a `watchlists/` folder, with `watchlists/example.yaml` provided.
- `.env.example` documents every supported key (Slack/webhook, AbuseIPDB, Shodan,
  NVD, SecurityTrails) with how-to-get links and free/paid status.
- JSON Schemas for playbooks/watchlists (`schemas/`) wired via `.vscode/settings.json`
  and per-file modelines, so editors validate against our format instead of
  mis-detecting the files as Ansible playbooks (gives `uses:` autocomplete too).
- Added dependencies: `node-cron`, `pdfkit`, `docx`.
- Version bumped 0.5.0 → 0.6.0.

## [0.5.0] - 2026-06-02

Phase 2 — Vulnerability intelligence. Seven new executors (six keyless, one
key-gated) and three new playbooks. The MCP server now exposes 23 executor tools
across 12 production playbooks.

### Added for 0.5.0

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

### Changed for 0.5.0

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

### Added for 0.4.0

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

### Changed for 0.4.0

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
