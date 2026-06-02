# Roadmap

This document tracks planned executors, features, playbooks, and integrations. Items are grouped by phase — Phase 1 is the immediate next focus, later phases are directional.

---

## Current state — v0.4.0

| Area | Status |
| ------ | -------- |
| 8 core executors (DNS, WHOIS, nmap, HTTP, TLS, subdomains, ping, traceroute) | ✅ Done |
| 8 Phase 1 executors (dns.reverse, email.security, ip.intel, http.security_score, http.waf_detect, http.fingerprint, tls.deep) | ✅ Done |
| MCP server with dynamic playbook-driven tool registration | ✅ Done |
| Input validation + command injection prevention across all executors | ✅ Done |
| 9 production playbooks (quick, basic, security, comprehensive, API/cloud, network, email-security, tls-deep, web-headers) | ✅ Done |
| CLI with `--target` flag, JSON + Markdown report output | ✅ Done |
| Full documentation suite | ✅ Done |

---

## Executor / check catalog  *(consolidated checklist)*

Single source of truth for every recon check — what ships today (✅) and what's
planned (⬜). Grouped by recon stage / `task_type`. Phase column links to the
detailed spec below.

### PASSIVE / OSINT  *(no host contact)*

| Check | Executor | Status | Phase |
| ----- | -------- | ------ | ----- |
| DNS records (A/AAAA/CNAME/NS/MX/TXT/PTR/SOA) | `dns.resolve` | ✅ | — |
| WHOIS registration | `whois.lookup` | ✅ | — |
| Passive subdomains (crt.sh) | `subdomains.passive` | ✅ | — |
| Reverse DNS / PTR sweep | `dns.reverse` | ✅ | — |
| Email security (DMARC/DKIM/SPF/MTA-STS/BIMI) | `email.security` | ✅ | — |
| ASN / IP intelligence (abuse reputation key-gated) | `ip.intel` | ✅ | — |
| Shodan host data | `shodan.host` | ⬜ | P2 |
| Passive DNS history | `securitytrails.*` | ⬜ | P4 |

### LIVENESS

| Check | Executor | Status | Phase |
| ----- | -------- | ------ | ----- |
| ICMP ping | `network.ping` | ✅ | — |
| Traceroute | `network.traceroute` | ✅ | — |

### PORTSCAN  *(active)*

| Check | Executor | Status | Phase |
| ----- | -------- | ------ | ----- |
| TCP connect + version scan | `nmap.scan` | ✅ | — |
| CVE lookup from service versions | `vuln.cve_lookup` | ⬜ | P2 |
| UDP scan | `nmap.udp` | ⬜ | P2 |
| OS fingerprint | `nmap.os` | ⬜ | P2 |

### WEBSCANNER  *(active)*

| Check | Executor | Status | Phase |
| ----- | -------- | ------ | ----- |
| HTTP headers + server banner | `http.headers` | ✅ | — |
| HTTP GET (body/status) | `http.get` | ✅ | — |
| TLS cert metadata | `tls.inspect` | ✅ | — |
| Security-header A–F score | `http.security_score` | ✅ | — |
| Deep TLS (weak ciphers, proto, chain, OCSP) | `tls.deep` | ✅ | — |
| WAF / CDN fingerprint | `http.waf_detect` | ✅ | — |
| Technology stack fingerprint | `http.fingerprint` | ✅ | — |
| CORS misconfiguration | `http.cors_check` | ⬜ | P2 |
| HTTP methods (OPTIONS/TRACE/PUT) | `http.methods` | ⬜ | P2 |

### ESCALATE  *(targeted, active — today via `http.get` playbook steps)*

| Check | Executor | Status | Phase |
| ----- | -------- | ------ | ----- |
| Exposure probes (.env/.git/admin/backup/swagger) | `http.get` steps | ✅ | — |
| Git repo leak detector | `http.git_leak` | ⬜ | P2 |
| Directory / path fuzzer | `http.fuzz_paths` | ⬜ | P2 |
| Cloud storage bucket finder | `cloud.bucket_finder` | ⬜ | P2 |
| Nuclei template scan | `nuclei.scan` | ⬜ | P4 |

**Today: 16 checks live ✅ · ~11 planned ⬜.** The `task_type` enum stays at four
(OSINT / PORTSCAN / WEBSCANNER / PASSIVE) — every planned check slots into one of them.
When a planned executor ships, flip its box to ✅ here and mirror it in CyberAgent's
`distillation/pipeline/tools.py` `TOOL_CATALOG` + flowchart.

---

## Phase 1 — Deeper intelligence  *(next)*

### New executors

#### Email security analyser

Full analysis of a domain's email security posture — goes beyond what the DNS executor returns.

- DMARC policy check (`_dmarc.<domain>`) — policy, `p=`, `rua`, `ruf`
- DKIM key discovery (`default._domainkey.<domain>`, common selectors)
- SPF record walk (follows `include:` chains, detects `+all` / `?all` misconfigs)
- MTA-STS policy check
- BIMI record detection

```yaml
- name: Email Security
  uses: email.security
  with:
    selectors: ["default", "google", "selector1", "selector2"]
```

#### SSL/TLS deep analyser

Extends the existing `tls.inspect` with vulnerability checks:

- Protocol support (TLS 1.0, 1.1 — should be disabled)
- Weak cipher detection (RC4, 3DES, NULL)
- Certificate chain validation (untrusted root, incomplete chain)
- OCSP stapling check
- HSTS preload status
- Certificate Transparency log verification

```yaml
- name: Deep TLS Analysis
  uses: tls.deep
  with:
    port: 443
    checkVulns: true
```

#### HTTP security headers scorer

Structured scoring of all security-relevant response headers — produces a letter grade (A–F) with per-header findings.

Headers evaluated: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-*`, `Clear-Site-Data`

```yaml
- name: Security Header Score
  uses: http.security_score
  with:
    path: "/"
```

#### WAF / CDN fingerprinter

Detects WAF and CDN presence from response headers, error pages, and timing characteristics.

Detects: Cloudflare, AWS WAF, Akamai, Imperva/Incapsula, F5 BIG-IP, Sucuri, Fastly, Varnish, Azure Front Door

```yaml
- name: WAF Detection
  uses: http.waf_detect
```

#### ASN / IP intelligence

Enriches discovered IP addresses with:

- ASN lookup (autonomous system name and number)
- BGP prefix / CIDR block
- Country and organisation
- IP abuse reputation (AbuseIPDB public API)
- Hosting provider detection (cloud vs. on-prem vs. CDN)

```yaml
- name: IP Intelligence
  uses: ip.intel
  with:
    ip: "104.26.14.170"
```

#### Technology stack fingerprinter

Identifies the technology stack from HTTP headers and body patterns — framework, server, CMS, analytics, CDN, JavaScript libraries.

```yaml
- name: Tech Fingerprint
  uses: http.fingerprint
  with:
    path: "/"
    deep: true
```

### New playbooks

| Playbook | Steps | Focus |
| ---------- | ------- | ------- |
| `email-security-assessment` | ~10 | DMARC · DKIM · SPF · MTA-STS · BIMI |
| `tls-deep-assessment` | ~8 | Protocol support · weak ciphers · chain · OCSP · CT logs |
| `web-headers-assessment` | ~5 | Full header scoring with A–F grade |

---

## Phase 2 — Vulnerability intelligence

### New executors

#### CVE lookup

Cross-references open ports and service versions (from nmap `-sV` output) against the National Vulnerability Database (NVD API v2).

- Parses nmap service/version output
- Queries NVD for matching CPE entries
- Returns CVE IDs, CVSS scores, severity, and descriptions
- No API key required for basic use (NVD public API)

```yaml
- name: CVE Lookup
  uses: vuln.cve_lookup
  with:
    nmapOutputStep: "Port scan"   # reference a previous nmap step's output
    minCvss: 5.0
```

#### Shodan host lookup

Enriches a target IP with Shodan's indexed data — open ports, services, banners, CVEs, and historical snapshots. Requires a Shodan API key.

```yaml
- name: Shodan Lookup
  uses: shodan.host
  with:
    apiKey: "{{env.SHODAN_API_KEY}}"
```

#### Directory / path fuzzer

Active path enumeration using a built-in wordlist (or custom list).

```yaml
- name: Path Discovery
  uses: http.fuzz_paths
  with:
    wordlist: "common"        # built-in: common | api | admin | php | asp
    threads: 10
    timeoutMs: 5000
```

#### Cloud storage bucket finder

Checks for publicly accessible cloud storage buckets derived from the target domain name.

- AWS S3: `<target>.s3.amazonaws.com`, `s3.amazonaws.com/<target>`
- GCP: `storage.googleapis.com/<target>`
- Azure: `<target>.blob.core.windows.net`

```yaml
- name: Cloud Bucket Discovery
  uses: cloud.bucket_finder
```

#### Git repository leak detector

Checks for exposed `.git` directory and reconstructs leaked content indicators:

- `.git/HEAD`, `.git/config`, `.git/COMMIT_EDITMSG`
- Detects remote origin URL, last commit message, author
- Flags as critical if data is accessible

```yaml
- name: Git Leak Detection
  uses: http.git_leak
```

### Report enhancement

- CVSS-based severity classification for each finding
- Executive summary section auto-generated at the top of Markdown reports
- Risk matrix table (Critical / High / Medium / Low / Info)
- Remediation suggestions per finding type

### New playbooks

| Playbook | Steps | Focus |
| ---------- | ------- | ------- |
| `vulnerability-assessment` | ~15 | CVE lookup · Shodan · bucket finder · git leak |
| `owasp-top10-recon` | ~20 | Recon phase for each OWASP Top 10 category |
| `cloud-security-assessment` | ~25 | AWS/GCP/Azure storage · cloud metadata endpoints · CDN misconfig |

---

## Phase 3 — Scale and automation

### Parallel step execution

Steps tagged `parallel: true` will run concurrently instead of sequentially — significantly reducing runtime for large playbooks.

```yaml
steps:
  - name: DNS Records
    uses: dns.resolve
    parallel: true          # runs at the same time as the next step

  - name: WHOIS
    uses: whois.lookup
    parallel: true
```

### Scheduled scanning

Integration with the Claude Desktop scheduled tasks system — run a playbook against a target on a cron schedule and get notified when new findings appear.

```bash
# Run quick-web-recon on cyberany.org every Monday at 08:00
npm run schedule -- --playbook quick-web-recon --target cyberany.org --cron "0 8 * * 1"
```

### Diff reports

Compare two runs against the same target and highlight what changed — new open ports, new subdomains, expired certificates, changed headers.

```bash
node src/index.js diff runs/run-2026-03-01.json runs/run-2026-04-01.json
```

### Target watchlist

Define a list of targets and playbooks in a YAML file and run the full batch in one command:

```yaml
# watchlist.yml
targets:
  - host: cyberany.org
    playbooks: [quick-web-recon, web-security-recon]
  - host: api.cyberany.org
    playbooks: [api-cloud-recon]
```

```bash
node src/index.js watch --list watchlist.yml
```

### PDF / DOCX report export

Generate professional cybersecurity assessment reports in PDF or DOCX format from any run's JSON output — with executive summary, findings table, remediation guidance, and company branding support.

```bash
node src/index.js report runs/run.json --format pdf --out report.pdf
```

### Webhook / notification support

Send findings to Slack, Teams, email, or a custom webhook when a playbook run completes or a critical finding is detected.

```yaml
# .env
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
NOTIFY_ON_SEVERITY=high,critical
```

---

## Phase 4 — Community and ecosystem

### Plugin system for custom executors

Package and share executors as npm plugins. Install a community executor with one command:

```bash
npm install mcp-recon-executor-nikto
```

It auto-registers in `runner.js` and appears in the MCP tool list.

### SecurityTrails integration

Enrich DNS and subdomain results with SecurityTrails historical data — useful for finding old infrastructure, shadow IT, and infrastructure changes over time. Requires a SecurityTrails API key.

### Nuclei integration

Run [Nuclei](https://github.com/projectdiscovery/nuclei) templates against a target and return structured findings. Nuclei has thousands of community-maintained templates covering CVEs, misconfigs, and exposed panels.

```yaml
- name: Nuclei Scan
  uses: nuclei.scan
  with:
    templates: ["cves", "exposed-panels", "misconfiguration"]
    severity: ["critical", "high", "medium"]
```

### Web dashboard

A local web UI served by the MCP server for browsing historical runs, comparing reports, and triggering new scans — without needing the CLI.

### Authentication-aware scanning

Support for scanning behind login walls — cookie injection, Bearer token headers, Basic Auth — so web security checks can reach authenticated content.

```yaml
vars:
  authHeader: "Bearer {{env.API_TOKEN}}"

steps:
  - name: Authenticated API Scan
    uses: http.headers
    with:
      path: "/api/v1/users"
      headers:
        Authorization: "{{vars.authHeader}}"
```

---

## Contributing

If you want to work on a roadmap item or propose a new one:

1. Open an issue or pull request on GitHub.
2. For new executors: follow the pattern in [Creating Playbooks](creating-playbooks.md#adding-a-custom-executor).
3. For new playbooks: drop a `.md` file in `playbooks/` — they auto-register with zero code changes.
