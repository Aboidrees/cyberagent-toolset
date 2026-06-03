# CyberAgentToolSet (CATS) — Full Project Report

## 1. What it is today

CyberAgentToolSet (CATS) — formerly `mcp-recon-runner` — is an MCP server **and** CLI that orchestrates **authorized** security assessments across the attack lifecycle. Capabilities ship as installable **extensions** (domain modules), the core is a small **engine + catalog**, and everything is driven by YAML playbooks and the Model Context Protocol so Claude (or any MCP client) can run it conversationally.

- **Version:** v0.11.0
- **Scale:** 51 executors across 15 extensions → 68 MCP tools (51 executors + 13 playbooks + 4 orchestration)
- **Repo:** [github.com/Aboidrees/cyberagent-toolset](https://github.com/Aboidrees/cyberagent-toolset) (public)
- **Wiki:** live at `/wiki` (15 pages)
- **Keyless by default;** optional keys add enrichment; runs as CLI or MCP server.

**Quick start:**

```bash
git clone https://github.com/Aboidrees/cyberagent-toolset.git && cd cyberagent-toolset && npm install
node src/index.js -p playbooks/quick-web-recon.yaml --target example.com   # CLI run
npm run mcp                                                                 # MCP server for Claude
```

## 2. The journey — how it got here

It started at ~v0.3.0 with ~9 core executors (DNS, WHOIS, nmap, HTTP, TLS, subdomains, ping, traceroute). Across this engagement it went through several major bodies of work:

| Stage | Version | Headline | Result |
| ----- | ------- | -------- | ------ |
| Phase 1 — Deeper intelligence | 0.4.0 | +7 executors (reverse DNS, email auth, IP/ASN intel, A–F header score, WAF detect, tech fingerprint, deep TLS) + 3 playbooks | 16 executors |
| Phase 2 — Vulnerability intelligence | 0.5.0 | +7 executors (NVD CVE lookup, Shodan, cloud buckets, path fuzz, .git leak, CORS, HTTP methods) + 3 playbooks | 23 executors · PR #1 merged |
| Phase 3 — Scale & automation | 0.6.0 | Parallel steps, scheduling, diffing, watchlists, PDF/DOCX/HTML export, webhooks, findings rollup; CLI subcommands; playbooks .md→.yaml; JSON schemas | PR #2 merged |
| Refactor → CyberAgentToolSet (CATS) | 0.7.0 | Rename + extension architecture (domain-first, catalog-driven, local + npm plugins); .env auto-loading; user guide; full wiki source | PR #3 merged |
| Phase 4 — Tool expansion | 0.8.0 | +17 executors (keyless batch +12, key-gated intel +4) + Nuclei multiplier; 40/40 self-test; wiki published | PR #4 merged |
| Phase 5 — Hardening + safe mode | 0.9.0 | CI + LICENSE; passive-only `--passive`; target-aware `auto`; `capabilities` listing; phase-grouped reports | PR #5 merged |
| Phase 6 — Tool expansion | 0.10.0 | +3 keyless executors (`vuln.epss`, `http.graphql`, `dns.txt_fingerprint`); 43/43 self-test | PR #6 open |
| Phase 7 — Tool expansion | 0.11.0 | +8 keyless executors (`rdap.lookup`, `cert.ctlog`, `web.security_txt`, `web.well_known`, `http.favicon_hash`, `dns.zone_transfer`, `smtp.probe`, `ssh.audit`) + `rdap`/`ssh` extensions; 51/51 self-test | PR #7 open |

## 3. Architecture (current)

**Core = engine + catalog. Nothing hardcodes executors anymore.**

- **Extensions = domain modules** under `extensions/<domain>/`. Each ships an `index.js` descriptor (the "manifest") declaring its executors, plus `src/*.js` implementations and an optional `report.js` that owns its findings extraction. The 15 domains: `dns, whois, rdap, email, ip-intel, threat-intel, securitytrails, censys, github-leaks, network, web, tls, ssh, cloud, nuclei`.
- **Classification metadata** on every executor: `phase` (reconnaissance / scanning / gaining-access), `posture` (passive / active), `domain`, `targetTypes` (domain/ip/cidr/url/email), and `permissions` (network egress, env keys, bins). This is decoupled from the `uses:` key — reclassifying never changes the key, so playbooks never churn.
- **Loader** (`src/extensions/loader.js`) — `loadCatalog()` discovers descriptors and builds the `uses → run` registry, executor metadata, report owners, and phase/domain views. Memoized.
- **Discovery, two sources:** local `extensions/` (out of the box) and npm packages named `cyberagent-ext-*` / `@cyberagent/ext-*` (auto-registered — proven end-to-end).
- **Shared services:** local extensions import `#sdk` (`validateTarget`, OS helpers, severity helpers); the same services are injected as the `ctx` third argument of every `run(target, opts, ctx)` so npm plugins need no core internals.
- **Runner** (`src/runner.js`) — YAML playbooks, `{{vars.X}}` + `{{env.X}}` templating, parallel steps (`parallel: true`), per-step timeouts, findings rollup, report writing.
- **MCP server** (`src/mcp-server.js`) — generates one `cats_<uses>` tool per executor + `cats_capabilities` (live phase/posture/domain view) + orchestration (`cats_topics/run/run_multi`) + per-playbook tools (`cats_play__<id>`).
- **Out of scope by design:** `maintaining-access` (post-exploitation) and `covering-tracks` (anti-forensics) are vocabulary only — never implemented, keeping the tool on the right side of the dual-use line.

## 4. The 51 executors

**Reconnaissance — passive** (no packets to the target host):
`dns.resolve` · `dns.reverse` · `dns.dnssec` · `dns.caa` · `dns.txt_fingerprint` · `subdomains.passive` · `whois.lookup` · `rdap.lookup` · `cert.ctlog` · `email.security` · `ip.intel` · `shodan.host`\* · `vuln.cve_lookup` · `vuln.epss` · `web.wayback` · `securitytrails.subdomains`\* · `securitytrails.dns_history`\* · `censys.host`\* · `github.leaks`\*

**Scanning / active recon:**
`subdomains.bruteforce` · `dns.zone_transfer` · `http.robots` · `web.security_txt` · `web.well_known` · `http.favicon_hash` · `network.ping` · `network.traceroute` · `nmap.scan` · `nmap.udp` · `nmap.os` · `network.banner` · `ssh.audit` · `smtp.probe` · `http.headers` · `http.get` · `http.security_score` · `http.waf_detect` · `http.fingerprint` · `http.cors_check` · `http.methods` · `http.cookies` · `http.open_redirect` · `http.subdomain_takeover` · `http.graphql` · `tls.inspect` · `tls.deep` · `nuclei.scan` (thousands of templates)

**Gaining access — read-only exposure:**
`http.fuzz_paths` · `http.git_leak` · `http.secrets` · `cloud.bucket_finder`

> `*` = key-gated (no-op note until the key is set). Nuclei needs the `nuclei` binary (no-op without it).

**Phase split:** reconnaissance 25 · scanning 22 · gaining-access 4.

## 5. Production playbooks

12 production playbooks plus a diagnostic and a skeleton. Drop a `.yaml` in `playbooks/` and it auto-registers as an MCP tool — no code changes.

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

Plus **`all-tools-selftest`** (diagnostic — exercises all 51 executors) and **`_template.yaml`** (authoring skeleton).

## 6. Automation, reporting, and config

- **Reports:** every run writes JSON + Markdown with an executive summary, risk matrix, and severity-rated findings rollup. Export to PDF / DOCX / HTML (`report` command, `--company` branding) via pdfkit/docx.
- **CLI commands:** `run` (default) · `diff` (compare two runs, non-zero exit on change) · `watch` (batch a YAML watchlist) · `schedule` (cron via node-cron) · `report`.
- **Notifications:** Slack + generic webhook on completion, gated by `NOTIFY_ON_SEVERITY`.
- **API keys / `.env`:** loaded automatically (CLI + MCP, resolved relative to install, dotenv runs quiet so it can't corrupt MCP stdio); real env vars win. Documented in `.env.example` with how-to-get + free/paid: Shodan, NVD, AbuseIPDB, SecurityTrails, Censys, GitHub token, Slack/webhook.
- **Playbooks & watchlists:** YAML, schema-validated (`schemas/playbook.schema.json` + `watchlist.schema.json`, wired via `.vscode/settings.json` + per-file modelines so editors don't misdetect them as Ansible). The `uses` enum is regenerated from the catalog via `schemas/build.mjs`.

## 7. Security model (the tool's own posture)

A security tool's own safety matters. CATS:

- **Target validation** — every executor runs `validateTarget` (allow-listed hostnames / IPv4 / IPv6 / CIDR; blocks shell metacharacters) before any network or shell use.
- **No shell interpolation** — external binaries (nmap, ping, traceroute, nuclei) run via `execFile` with argument arrays, never `exec`; nmap flags are allow-list validated.
- **SSRF / host-override guard** — `buildUrl` whitelists the scheme to http/https and rejects paths containing credentials (`@`), whitespace, control characters, backslashes, or a protocol-relative (`//`) prefix.
- **Memory-exhaustion guard** — all HTTP GETs cap response body size (`maxContentLength`).
- **Untrusted-data validation** — third-party responses are validated before reuse (e.g. the Team Cymru ASN must be numeric before it is interpolated into a follow-up DNS query).
- **Secret hygiene** — `.env` is gitignored; key-gated executors no-op without keys; each extension declares its egress/env/bins in `permissions`.
- **Ethical framing** — authorized-assessment warnings throughout; post-exploitation and anti-forensics are intentionally unimplemented.

## 8. Tech stack & repository layout

- **Runtime:** Node ≥ 18, ES modules. **Bins:** `cyberagent` (CLI), `cyberagent-mcp` (MCP server).
- **Dependencies (10):** `@modelcontextprotocol/sdk` (MCP), `axios` (HTTP), `js-yaml` + `gray-matter` (playbook parsing), `yargs` (CLI), `node-cron` (scheduling), `pdfkit` + `docx` (report export), `dotenv` (.env), `whois-json` (WHOIS). Optional external binaries: `nmap`, `traceroute`, `nuclei`.

```text
src/            engine — index.js (CLI) · mcp-server.js · runner.js · sdk.js · env.js
                diff.js · watch.js · schedule.js · report.js
                extensions/loader.js · utils/ (findings · validate · os · fsx · logger · playbooks)
extensions/     13 domain modules — each: index.js (descriptor) + src/*.js + report.js
playbooks/      13 YAML playbooks + _template.yaml
watchlists/     batch target lists (example.yaml)
schemas/        playbook/watchlist JSON Schemas + build.mjs
docs/           in-repo documentation
wiki/           GitHub wiki source + publish.sh
runs/           generated reports (gitignored)
```

## 9. Documentation & wiki

- **In-repo docs:** `architecture.md`, `user-guide.md` (scenario-driven), `executors.md` (all 51), `playbooks.md`, `creating-playbooks.md` (extension authoring), `configuration.md`, `installation.md`, `mcp-integration.md`, `troubleshooting.md`, `roadmap.md`, plus README and CHANGELOG.
- **GitHub wiki (live):** 15 pages — Home, Quick Start, User Guide, CLI Reference, Playbooks, Executors, Extensions, API Keys, MCP Integration, Architecture, Automation, Troubleshooting, FAQ, Installation, Sidebar. Source lives in `wiki/`; `wiki/publish.sh` syncs it.

## 10. Verification posture

The project has **no automated test framework by design** (executors are live-network). The regression oracle is the `all-tools-selftest` playbook, which exercises every executor once — currently **51/51 green**. Every phase kept it green; every executor was also smoke-tested live; the MCP server boots clean; `node --check` passes on all source; npm-plugin discovery was proven with a throwaway extension. Each phase shipped via its own PR with an adversarial pre-landing review (which caught real bugs: SSRF/host-override in URL building, ASN injection, TLS timer leaks, the CONNECT-method hang, multi-request timeout coupling, banner SYN-drop hang).

## 11. Known limitations & honest gaps

- **No unit/integration tests** — by design (live-network); the 51/51 self-test is the oracle, but it needs network and isn't a substitute for fast unit tests.
- **CI** *(added v0.9.0)* — GitHub Actions runs a deterministic validate gate + a self-test smoke job on every PR.
- **License** *(added v0.9.0)* — a `LICENSE` file (MIT) is now committed.
- **Not published to npm** — install is `git clone`; the `cyberagent-ext-*` plugin convention works, but no extension is on the registry yet and there's no starter-template repo.
- **Root-only checks** — `nmap.udp` / `nmap.os` no-op without root.
- **Environment-sensitive executors** — some DNS-heavy checks depend on the local resolver; a slow resolver can make them time out (bounded internally, but worth noting).
- **Dependency advisories** — `npm audit` reports transitive advisories (axios/js-yaml/pdfkit/docx trees); not yet remediated.
- **Wiki re-sync is manual** — `wiki/publish.sh` (needs a public repo, now satisfied).

## 12. Where things stand

- **Merged to `main`:** Phases 1+2 (PR #1), Phase 3 (PR #2), CATS refactor (PR #3), Phase 4 expansion (PR #4).
- **Open:** PR #5 — Phase 5 hardening (CI, LICENSE) + safe mode (`--passive`), `auto`, `capabilities`, phase-grouped reports. Awaiting review/merge.
- Repo is public; wiki is live and current.

## 13. The plan / roadmap forward

**Immediate:** merge PR #4.

**Capabilities the metadata already unlocks** (cheap follow-ups, not yet built):

- ✅ **Passive-only / safe mode** *(shipped v0.9.0)* — `--passive` skips active executors.
- ✅ **Target-aware auto-assembly** *(shipped v0.9.0)* — the `auto` command runs every applicable executor for a target.
- ✅ **Phase-grouped reports & tool listing** *(shipped v0.9.0)* — `capabilities` command + "Coverage / Findings by phase" in reports.

**More tools** (the architecture makes each a small descriptor):

- Deeper service probes (SMB/SNMP), web screenshotting (headless), more cloud providers and bucket object/ACL listing. *(GraphQL introspection, TXT fingerprinting, EPSS scoring shipped in Phase 6; RDAP, CT-log history, security.txt/well-known, favicon hashing, AXFR, SMTP + SSH audits shipped in Phase 7.)*
- More key-gated intel providers (e.g. hunter.io email harvesting) following the established no-op-without-key pattern.
- Deeper Nuclei wiring (template management, tag presets).

**Ecosystem & hardening:**

- A starter `cyberagent-ext-*` template repo so third parties have a paved path to publish extensions.
- Optional: enforce the `permissions` manifest as a runtime safety control (block undeclared egress/env access from third-party plugins).

> **Explicitly not on the roadmap:** post-exploitation (`maintaining-access`) and anti-forensics (`covering-tracks`) — out of scope by design.

**Trajectory at a glance:** 9 → 16 → 23 → (refactor) → 40 → 43 → 51 executors + Nuclei (≈thousands of checks), with the cost of adding the next tool now near-zero thanks to the extension model.

---

## 14. Glossary — key terms (what each is and what it does)

### Core / engine

- **Engine** — the runtime core of the tool: the loader + runner + MCP server + report aggregator working together. It discovers capabilities, runs playbooks, and produces reports. It deliberately contains none of the actual security checks (those live in extensions). Think of it as the chassis; executors are the parts you bolt on.
- **Catalog** — the in-memory index the engine builds once at startup from every installed extension. Holds the registry (`uses → run`), each executor's metadata (phase/posture/domain/targetTypes/summary), the report owners, and phase/domain groupings. The single source of truth for "what tools exist right now," including npm-installed plugins.
- **Loader** (`src/extensions/loader.js`) — the component that finds extensions (local `extensions/` folders and npm `cyberagent-ext-*` packages), validates their descriptors, and assembles the catalog. Runs once per process (memoized).
- **Registry** — the lookup table inside the catalog mapping a `uses` key (e.g. `dns.resolve`) to the function that actually runs it. The runner and MCP server dispatch through it.

### Capabilities

- **Executor** — the atomic unit of capability: one self-contained check or action (resolve DNS, grade security headers, probe for open redirect, …). Takes a target plus options and returns structured data, optionally including findings. Addressed by a stable `uses` key and tagged with classification metadata. There are 51.
- **Extension** — a domain module packaging one or more related executors (e.g. the `web` extension ships all the `http.*` executors), with their shared helper code and an optional report module. The unit of distribution: a local folder under `extensions/`, or an npm package. There are 13.
- **Descriptor** (a.k.a. manifest) — the object an extension's `index.js` default-exports. Declares the extension's name/version/domain/description, the executors with their metadata and run functions, the permissions it needs, and an optional report module. This is what the loader reads to register everything.
- **Domain** — the capability area an extension covers (dns, web, tls, cloud, network, nuclei, …). The organizing/folder dimension; related code stays together for cohesion.
- **Report module** (`report.js`) — an extension-owned function `findings(stepOutput)` that turns one executor's raw result into severity-rated findings. The engine calls each extension's report module and aggregates the results, so domain knowledge stays with the domain.

### Classification metadata

- **`uses` key** — an executor's stable logical id (e.g. `http.security_score`). The contract that playbooks and MCP tools reference. It never changes when an executor is re-classified, so playbooks never break.
- **Phase** — where an executor sits in the attack lifecycle: reconnaissance, scanning, or gaining-access. (`maintaining-access` and `covering-tracks` exist as vocabulary but are intentionally never implemented — no post-exploitation or anti-forensics.)
- **Posture** — whether an executor sends traffic to the target host: **passive** (no packets reach the host — DNS, crt.sh, Wayback, third-party APIs) or **active** (direct contact — nmap, HTTP requests, fuzzing). Drives the "authorized targets only" warnings and a future passive-only safe mode.
- **`targetTypes`** — the kinds of input an executor accepts: domain, ip, cidr, url, email. Used (now and in planned auto-assembly) to pick the right executors for a given target.
- **`permissions`** — what an extension declares it touches: outbound network protocols, environment-variable keys (API keys), and external binaries (nmap, nuclei). For transparency today and enforceable safe-mode tomorrow.

### Execution

- **Playbook** — a YAML file in `playbooks/` defining an `id`, `title`, `description`, default `vars`, and an ordered list of steps to run against one target. The primary way to run a coherent assessment; auto-registers as an MCP tool.
- **Step** — one entry in a playbook: a `name`, a `uses` (which executor to run), and a `with` block (the executor's options). May be flagged `parallel: true`.
- **Runner** (`src/runner.js`) — the component that loads a playbook, substitutes templates, runs the steps (sequentially, or concurrently in batches for parallel steps), aggregates findings, and writes the JSON + Markdown reports.
- **Parallel step** — consecutive steps marked `parallel: true` run concurrently as a batch; the next non-parallel step is a barrier. Output order always matches the playbook order.
- **Variable / templating** — playbook `vars` plus `{{vars.NAME}}` and `{{env.NAME}}` placeholders substituted at run time. Overridable with `--var` / `--target` on the CLI.
- **Target** — the host, domain, IP, or CIDR being assessed.

### Interface (MCP + CLI)

- **MCP (Model Context Protocol)** — the open protocol that lets an AI client (such as Claude) call local tools over a stdio JSON-RPC stream. It is how CATS plugs into Claude.
- **MCP server** (`src/mcp-server.js`) — the process that exposes CATS capabilities as MCP tools so Claude can drive the whole workflow conversationally.
- **Tool (MCP tool)** — a single callable exposed to the MCP client. CATS publishes one `cats_<uses>` tool per executor, one `cats_play__<id>` per playbook, and the orchestration tools. 68 in total today.
- **Orchestration tools** — the non-executor MCP tools: `cats_capabilities` (list every executor by phase/posture/domain), `cats_topics` (list playbooks), `cats_run` and `cats_run_multi` (run one or many playbooks).
- **CLI** — the command-line interface (`src/index.js`, installed bin `cyberagent`). Subcommands: `run` (default), `diff`, `watch`, `schedule`, `report`.

### Extensibility

- **SDK (`#sdk`)** — the small, stable set of shared services local extensions import (`validateTarget`, OS/command helpers, severity helpers). The contract third-party code builds against; keeping it small keeps plugins stable across versions.
- **`ctx`** — the shared-services object the engine injects as the third argument of every executor's `run(target, opts, ctx)`. Lets npm-installed plugins use `ctx.validateTarget` etc. without importing any core internals.
- **npm plugin (`cyberagent-ext-*`)** — an extension distributed as an npm package. Installing one (`npm install cyberagent-ext-foo`) makes the loader auto-discover and register it — no code changes.

### Output / findings

- **Finding** — a single severity-rated issue an executor surfaces (e.g. "TLS 1.0 supported", "exposed .git directory"), with a severity and a message. Collected across a whole run.
- **Severity** — the rating scale for findings: critical, high, medium, low, info.
- **Report** — the output of a run. Always JSON + Markdown (executive summary, risk matrix, findings list, per-step results), and exportable to PDF / DOCX / HTML via the `report` command.
- **Executive summary / risk matrix** — the rollup at the top of every report: a one-line severity summary and a counts table (critical/high/medium/low/info), so the headline is readable before the detail.

### Automation

- **Watchlist** — a YAML file (`watchlists/`) listing targets and, per target, the playbooks to run against them, for batch assessment via the `watch` command.
- **Diff** — comparing two run JSONs to highlight what changed (new/removed ports, subdomains, DNS records, certificate changes, new/resolved findings). Exits non-zero on change, for monitoring.
- **Schedule** — recurring runs on a cron expression (via node-cron); new findings can fire notifications.
- **Webhook / notification** — a run summary POSTed to Slack and/or a generic endpoint on completion, gated by `NOTIFY_ON_SEVERITY`.

### Configuration

- **`.env`** — the environment file (gitignored) holding API keys and webhook config. Loaded automatically at startup for both the CLI and the MCP server, and for both built-in and npm extensions. Real shell env vars take precedence.
- **Key-gated** — an executor that needs an API key (Shodan, SecurityTrails, Censys, GitHub, AbuseIPDB enrichment). Without the key it returns a short "set the key" note instead of failing, so it can safely sit in a playbook.
- **Schema** — JSON Schemas (`schemas/`) that validate playbooks and watchlists in editors (and stop them being mis-detected as Ansible). The playbook schema's list of valid `uses` keys is regenerated from the catalog with `schemas/build.mjs` so it never drifts.

### Tooling-specific

- **Nuclei** — an external open-source scanner with thousands of community-maintained templates (CVEs, exposures, misconfigurations, takeovers, default creds). CATS wraps it as the `nuclei.scan` executor — the "multiplier," because one executor pulls in that whole template library. No-ops with a note when the `nuclei` binary isn't installed.
- **Template (Nuclei)** — a single Nuclei check definition (one CVE, one exposure rule, etc.). Nuclei ships thousands; `nuclei.scan` runs the chosen set against the target.
- **Self-test / regression oracle** — the `all-tools-selftest` playbook, which exercises every executor exactly once. Because the project intentionally has no unit-test framework (the checks are live-network), this playbook passing 51/51 is the main correctness signal after any change.
