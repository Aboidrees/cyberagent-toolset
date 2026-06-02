---
id: cloud-security-assessment
title: Cloud Security Assessment
vars:
  target: "example.com"
  scheme: "https"
  timeout: 10000
steps:
  # ── Hosting & infrastructure mapping ──────────────────────────────────────
  - name: IP / ASN Intelligence
    uses: ip.intel

  - name: DNS Records (CNAME reveals cloud/CDN)
    uses: dns.resolve
    with:
      types: ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]
      timeoutMs: 8000

  - name: WAF / CDN Fingerprint
    uses: http.waf_detect
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # ── Cloud storage exposure ────────────────────────────────────────────────
  - name: Cloud Bucket Discovery
    uses: cloud.bucket_finder
    with:
      timeoutMs: 30000        # step budget (per-probe bounded internally)

  # ── Subdomain & shadow-infrastructure surface ─────────────────────────────
  - name: Passive Subdomains (crt.sh)
    uses: subdomains.passive
    with:
      sources: ["crtsh"]
      timeoutMs: 25000        # crt.sh can be slow for domains with large cert history

  # ── Shodan host intelligence (key-gated) ──────────────────────────────────
  - name: Shodan Host Data
    uses: shodan.host
    with:
      timeoutMs: 15000

  # ── Transport & edge security ─────────────────────────────────────────────
  - name: Deep TLS Analysis
    uses: tls.deep
    with:
      port: 443
      timeoutMs: 10000

  - name: Security Header Score
    uses: http.security_score
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Technology Fingerprint
    uses: http.fingerprint
    with:
      path: "/"
      deep: true
      timeoutMs: "{{vars.timeout}}"

  # ── Common cloud-app exposures ────────────────────────────────────────────
  - name: Cloud Config Exposure (.env / .git)
    uses: http.git_leak
    with:
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: API Surface Discovery
    uses: http.fuzz_paths
    with:
      wordlist: "api"
      scheme: "{{vars.scheme}}"
      timeoutMs: 20000        # step budget (per-request bounded internally)
---

## Cloud Security Assessment for {{vars.target}}

Focuses on cloud-hosted application exposure: which provider hosts the target,
what storage is publicly reachable, and how the edge (CDN/WAF/TLS) is configured.

### What This Checks

- **Hosting provider** — ASN/IP intelligence + CNAME chains classify AWS / GCP /
  Azure / CDN
- **Edge** — WAF/CDN fingerprint and deep TLS configuration
- **Storage exposure** — public AWS S3, GCP Cloud Storage, and Azure Blob buckets
  derived from the domain name
- **Attack surface** — passive subdomains, API endpoints, and exposed `.git`
- **Shodan** — indexed services and CVEs (requires `SHODAN_API_KEY`)

### Notes

- `cloud.bucket_finder` only flags buckets that actually exist; `public`/
  `public-listable` access is the high-severity finding, `private` (403) means the
  bucket exists but is locked down.
- `shodan.host` is skipped with a note unless `SHODAN_API_KEY` is set.
- Cloud metadata endpoints (`169.254.169.254`) are intentionally out of scope —
  they are only reachable from inside the target's network, not via recon.

⚠️ Includes active steps (path fuzzing, bucket probing). Run only against
authorized targets.

### Usage

```bash
node ./src/index.js -p ./playbooks/cloud-security-assessment.md --var target=authorized-target.com
```
