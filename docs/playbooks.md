# Playbooks

Playbooks are Markdown files with a YAML front matter block that defines variables, steps, and metadata. The runner executes each step in order and saves the results.

---

## Available playbooks

### Quick Web Recon (`quick-web-recon`)

#### **8 steps · ~1–2 min**

Fast essentials optimised for speed. Best first pass before going deeper.

Steps: DNS A/AAAA → HTTPS headers → HTTP headers (fallback) → robots.txt → sitemap.xml → TLS certificate → subdomain enumeration

```bash
node src/index.js -p playbooks/quick-web-recon.md --target example.com
```

---

### Basic Web Recon (`web-basic-recon`)

#### **7 steps · ~3–5 min**

Standard baseline covering DNS, registration info, ports, web layer, and passive subdomains.

Steps: DNS (all types) → WHOIS → nmap top 1000 ports → HTTP headers → robots.txt → TLS → subdomains

```bash
node src/index.js -p playbooks/web-basic-recon.md --target example.com
```

---

### Web Security Recon (`web-security-recon`)

#### **51 steps · ~8–15 min**

Vulnerability-oriented. Probes for information disclosure, exposed developer artifacts, admin interfaces, and framework-specific issues.

Checks include: security headers · TLS config · `.env` (+ `.local`/`.production`/`.backup`) · VCS exposure (`.git`/`.svn`/`.hg`/`.bzr`) · cloud creds (`.aws/credentials`/`.npmrc`/`.pypirc`) · Docker files · `docker-compose.yml` · CI configs (`.gitlab-ci.yml`/GitHub Actions) · Spring Boot Actuator (`/actuator/health`/`/actuator/env`) · IDE artifacts (`.vscode`/`.idea`/`.DS_Store`) · web.config · `.htaccess` · phpinfo · backup files · admin/management panels · PHPMyAdmin · Swagger/GraphQL · server-status · WordPress/Laravel/Django leaks · logs · source maps · package.json · composer.json · `trace.axd` · `crossdomain.xml`

```bash
node src/index.js -p playbooks/web-security-recon.md --target example.com
```

---

### Comprehensive Web Recon (`comprehensive-web-recon`)

#### **37 steps · ~10–20 min**

Full sweep: DNS intelligence → WHOIS → passive subdomains → multi-range port scanning → complete web layer analysis → security header evaluation → technology fingerprinting → CMS detection → CDN/cloud identification.

```bash
node src/index.js -p playbooks/comprehensive-web-recon.md --target example.com
```

---

### API & Cloud Recon (`api-cloud-recon`)

#### **39 steps · ~5–10 min**

Built for modern applications. Discovers REST APIs, GraphQL, Swagger/OpenAPI docs, cloud-native health endpoints, service discovery (Consul/Eureka), API gateways, auth flows (OAuth/SAML/JWT), serverless functions, and CDN providers.

```bash
node src/index.js -p playbooks/api-cloud-recon.md --target api.example.com
```

---

### Network Connectivity Test (`network-connectivity-test`)

#### **2 steps · ~1 min**

Simple diagnostics: ICMP ping statistics + traceroute hop-by-hop path. Useful for confirming reachability and spotting routing anomalies before running deeper scans.

```bash
node src/index.js -p playbooks/network-connectivity-test.md --target example.com
```

---

### Email Security Assessment (`email-security-assessment`)

#### **3 steps · ~1 min**

Passive evaluation of a domain's email-authentication posture — SPF, DMARC, DKIM, MTA-STS, and BIMI — with severity-rated findings and an at-a-glance summary. No packets reach the mail servers (DNS lookups plus one HTTPS fetch for the MTA-STS policy). Safe to run against any domain.

```bash
node src/index.js -p playbooks/email-security-assessment.md --target example.com
```

---

### TLS Deep Assessment (`tls-deep-assessment`)

#### **3 steps · ~1–2 min**

Vulnerability-oriented TLS analysis — protocol support matrix (flags TLS 1.0/1.1), weak-cipher probes (RC4/3DES/NULL), certificate chain validation, OCSP stapling, and HSTS/preload status — alongside the baseline certificate metadata.

```bash
node src/index.js -p playbooks/tls-deep-assessment.md --target example.com
```

---

### Web Headers Assessment (`web-headers-assessment`)

#### **4 steps · ~1 min**

Focused look at the HTTP response surface: an A–F security-header grade with per-header remediation advice, a WAF/CDN fingerprint, and a technology-stack fingerprint.

```bash
node src/index.js -p playbooks/web-headers-assessment.md --target example.com
```

---

### All-Tools Self Test (`all-tools-selftest`)

#### **16 steps · ~3–5 min**

Diagnostic playbook that exercises **every executor exactly once** — dns.resolve, dns.reverse, whois.lookup, subdomains.passive, network.ping, network.traceroute, nmap.scan, http.headers, http.get, http.security_score, http.waf_detect, http.fingerprint, tls.inspect, tls.deep, email.security, ip.intel — so you can confirm the whole engine works against a real target in one run.

Steps: DNS → WHOIS → subdomains → ping → traceroute → nmap top 100 → HTTP headers → HTTP GET → TLS → reverse DNS → email security → IP intel → header score → WAF detect → tech fingerprint → deep TLS

> **Active + authorized only.** Includes nmap, ping, and traceroute; requires `nmap` and `traceroute` installed on the host. Run only against assets you own or are authorized to scan.

```bash
node src/index.js -p playbooks/all-tools-selftest.md --target example.com
```

---

## Playbook file format

```yaml
---
id: my-custom-recon          # required — used as MCP tool name suffix
title: My Custom Recon       # required — human label
vars:                        # default variable values
  target: "example.com"
  scheme: "https"
  timeout: 10000
steps:
  - name: DNS Records        # human label for this step
    uses: dns.resolve        # executor to call
    with:                    # options passed to the executor
      types: ["A", "AAAA", "NS", "MX", "TXT"]
      timeoutMs: 5000

  - name: HTTP Headers
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Port Scan
    uses: nmap.scan
    with:
      flags: "-sT --top-ports 1000"
      timeoutMs: 120000
---

## My Custom Recon for {{vars.target}}

Description shown in MCP tool listing and reports.
```

---

## Variable templating

Use `{{vars.name}}` anywhere in step `with` values to substitute playbook variables:

```yaml
vars:
  target: "example.com"
  scheme: "https"
  timeout: 10000
  topPorts: 1000

steps:
  - name: Port Scan
    uses: nmap.scan
    with:
      flags: "-sT --top-ports {{vars.topPorts}}"
      timeoutMs: "{{vars.timeout}}"
```

Override any variable at runtime:

```bash
# --target shorthand
node src/index.js -p playbooks/web-basic-recon.md --target example.com

# Fine-grained overrides
node src/index.js -p playbooks/web-basic-recon.md \
  --var target=example.com \
  --var scheme=http \
  --var topPorts=500
```

---

## Step execution rules

- Steps run **sequentially** in order.
- A failed step (`ok: false`) does **not** stop the playbook — remaining steps still run.
- Each step's result is saved to the report regardless of success or failure.
- `timeoutMs` at the step level overrides the global `--timeout` CLI flag.

---

## Adding your own playbook

1. Create `playbooks/my-playbook.md` with the YAML format above.
2. Make sure `id` and `title` are set.
3. If using with MCP: restart Claude Desktop — the new playbook auto-registers as a tool.
4. If using CLI: `node src/index.js -p playbooks/my-playbook.md --target example.com`

See [Creating Playbooks](creating-playbooks.md) for a step-by-step guide.
