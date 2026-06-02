---
id: <unique-id>
title: <human title>
vars:
  target: "example.com"
  scheme: "https"
  timeout: 10000
steps:
  - name: <step name>
    uses: dns.resolve|dns.reverse|whois.lookup|nmap.scan|http.headers|http.get|http.security_score|http.waf_detect|http.fingerprint|tls.inspect|tls.deep|subdomains.passive|email.security|ip.intel|network.ping|network.traceroute
    with: { ... executor-specific options ... }
---

## Playbook Templates and Examples

This file is the single-page reference for authoring reconnaissance playbooks. It
documents **every executor** — what it does, the options it accepts, and a ready
to-copy YAML snippet — grouped by the recon **stage** it belongs to.

A playbook is a Markdown file with a YAML front-matter block. The front matter
declares an `id`, a `title`, default `vars`, and an ordered list of `steps`. Each
step names an executor via `uses:` and passes executor-specific options under
`with:`. Drop a new `.md` file in `playbooks/` and it auto-registers as an MCP
tool — no code changes required.

### How options work

- **`with:`** holds executor-specific options (documented per-executor below).
- **`timeoutMs`** is special: the runner applies it as the **overall timeout for
  that step**. Most executors also use it internally (e.g. as their HTTP/TLS
  connect timeout), so a single `timeoutMs` value caps the whole step. If a step
  exceeds it, the step is marked failed and the run continues to the next step.
- **`{{vars.name}}`** templating substitutes values from the `vars:` block (or
  `--var` / `--target` overrides) into any string option. A whole-string numeric
  template (e.g. `"{{vars.port}}"`) is coerced back to a number automatically.

### Recon stages at a glance

| Stage | Host contact | Executors |
| ----- | ------------ | --------- |
| **PASSIVE / OSINT** | None — queries third parties (DNS, crt.sh, Team Cymru) | `dns.resolve`, `dns.reverse`, `whois.lookup`, `subdomains.passive`, `email.security`, `ip.intel` |
| **LIVENESS** | Light — ICMP / UDP probes to the host | `network.ping`, `network.traceroute` |
| **PORTSCAN** | Active — connects to ports on the host | `nmap.scan` |
| **WEBSCANNER** | Active — HTTP/TLS requests to the host | `http.headers`, `http.get`, `http.security_score`, `http.waf_detect`, `http.fingerprint`, `tls.inspect`, `tls.deep` |

> ⚠️ **Authorization:** LIVENESS, PORTSCAN, and WEBSCANNER stages send traffic to
> the target. Only run them against hosts you own or are explicitly authorized to
> test. PASSIVE / OSINT checks never touch the target and are always safe to run.

---

## Stage 1 — PASSIVE / OSINT

No packets reach the target. These checks gather intelligence from third parties:
authoritative DNS, certificate-transparency logs (crt.sh), WHOIS registries, and
Team Cymru's IP-to-ASN service. Safe to run first in any engagement.

### DNS Resolution (`dns.resolve`)

Resolves one or more DNS record types for a domain. `SOA` is fetched automatically
when not explicitly requested. Unresolvable record types come back as empty arrays
rather than errors.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `types` | string[] | `["A","AAAA"]` | Record types: `A`, `AAAA`, `CNAME`, `NS`, `MX`, `TXT`, `PTR`, `SOA` |
| `timeoutMs` | number | step default | Overall step timeout |

```yaml
- name: DNS Records
  uses: dns.resolve
  with:
    types: ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "PTR"]
    timeoutMs: 5000
```

### Reverse DNS / PTR Sweep (`dns.reverse`)

Reverse (PTR) lookup or sweep. Accepts a single IP, an IPv4 CIDR range (sweeps
every host in the range), or a hostname (resolves `A`/`AAAA` first, then reverses
each address). Returns a per-IP PTR map plus a flat, deduplicated name list.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `maxHosts` | number | `256` | Upper bound on addresses for a CIDR sweep (guards against huge ranges) |
| `timeoutMs` | number | step default | Overall step timeout |

```yaml
- name: PTR Sweep
  uses: dns.reverse
  with:
    maxHosts: 256        # target may be an IP, CIDR (e.g. 192.0.2.0/24), or hostname
```

### WHOIS Lookup (`whois.lookup`)

Queries WHOIS for a domain or IP — registrar, registration/expiry dates, name
servers, status flags, registrant, and abuse contact. Returns the parsed record.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `timeoutMs` | number | `15000` | Lookup timeout |

```yaml
- name: Domain Registration
  uses: whois.lookup
  with:
    timeoutMs: 15000
```

### Passive Subdomain Discovery (`subdomains.passive`)

Enumerates subdomains from certificate-transparency logs (crt.sh) without probing
the target. Returns a merged, deduplicated, sorted list plus the raw per-source
results.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `sources` | string[] | `["crtsh"]` | CT/OSINT sources to query |
| `timeoutMs` | number | `20000` | Per-source query timeout |

```yaml
- name: Passive Subdomains
  uses: subdomains.passive
  with:
    sources: ["crtsh"]
    timeoutMs: 15000
```

### Email Security (`email.security`)

Evaluates a domain's email-authentication posture — SPF, DMARC, DKIM, MTA-STS,
and BIMI — using passive DNS lookups plus one HTTPS fetch for the MTA-STS policy
file. All DNS lookups run concurrently and each is independently capped by
`dnsTimeoutMs`. Each sub-check returns a `findings` array with severities; a
top-level `summary` and rolled-up `findings` list aid triage. **No API key.**

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `selectors` | string[] | common set | DKIM selectors to probe (e.g. `default`, `google`, `selector1`) |
| `timeoutMs` | number | `8000` | MTA-STS policy fetch timeout (and overall step cap) |
| `dnsTimeoutMs` | number | `6000` | Per-DNS-lookup cap; bounds a single slow resolver response |

```yaml
- name: Email Security Posture
  uses: email.security
  with:
    selectors: ["default", "google", "selector1", "selector2"]
    timeoutMs: 20000      # generous step budget; DNS lookups capped internally
```

### ASN / IP Intelligence (`ip.intel`)

Enriches a target IP (or a hostname's resolved IP) with ASN, BGP prefix, country,
registry, allocation date, and a hosting/CDN classification — all via Team Cymru's
**keyless** DNS service. Abuse reputation (AbuseIPDB) is an **optional, key-gated**
add-on: it runs only when an API key is supplied, otherwise it is skipped with a note.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `ip` | string | resolved from target | Explicit IP to analyse instead of resolving the target |
| `apiKey` | string | `ABUSEIPDB_API_KEY` env | Enables AbuseIPDB reputation (optional) |
| `timeoutMs` | number | `8000` | AbuseIPDB request timeout (only used when a key is set) |

```yaml
- name: IP Intelligence
  uses: ip.intel
  with:
    ip: "104.26.14.170"   # optional; otherwise resolved from target
    # AbuseIPDB reputation runs only if ABUSEIPDB_API_KEY is set
```

---

## Stage 2 — LIVENESS

Lightweight probes that confirm a host is reachable and map the network path to
it. These send a small amount of traffic to the target.

### ICMP Ping (`network.ping`)

Sends ICMP echo requests and reports reachability, packet loss, and min/avg/max
latency. Requires `ping` in `PATH` (standard on macOS/Linux/Windows).

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `count` | number | `4` | Number of echo packets to send |
| `timeoutMs` | number | `30000` | Overall timeout |

```yaml
- name: Liveness Check
  uses: network.ping
  with:
    count: 4
    timeoutMs: 30000
```

### Traceroute (`network.traceroute`)

Traces the hop-by-hop network path to the target with per-hop latency. Hops marked
`timeout: true` are filtered/unreachable (`* * *`). Requires `traceroute`
(Unix/macOS) or `tracert` (Windows) in `PATH`.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `maxHops` | number | `30` | Maximum hop count |
| `timeoutMs` | number | `60000` | Overall timeout |

```yaml
- name: Network Path
  uses: network.traceroute
  with:
    maxHops: 20
    timeoutMs: 45000
```

---

## Stage 3 — PORTSCAN

Active port scanning. Connects to ports on the target — only run against
authorized hosts.

### Port Scan (`nmap.scan`)

Runs `nmap` against the target. Defaults to a non-privileged TCP connect scan of
the top 1000 ports. Flags are validated against an allow-list to prevent command
injection. Requires `nmap` installed on the host.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `flags` | string | `-sT -Pn --top-ports 1000` | nmap flags (allow-list validated) |
| `timeoutMs` | number | `300000` | Overall scan timeout |

```yaml
- name: Port Scan
  uses: nmap.scan
  with:
    flags: "-sT -Pn -sV --top-ports 1000"
    timeoutMs: 300000
```

> ⚠️ Only scan hosts you have explicit authorization to test. Use `-sT` (TCP
> connect) for non-privileged runs; SYN scans (`-sS`) require root.

---

## Stage 4 — WEBSCANNER

Active HTTP and TLS inspection of the target's web surface. All of these send
requests to the host.

### HTTP Headers (`http.headers`)

Fetches the response headers for a path — server banner, security headers (HSTS,
CSP, X-Frame-Options), cookies. Never throws on HTTP error status codes; follows
up to 5 redirects.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `path` | string | `/` | URL path to request |
| `scheme` | string | `https` | `http` or `https` |
| `timeoutMs` | number | `10000` | Request timeout |

```yaml
- name: HTTP Headers
  uses: http.headers
  with:
    path: "/"
    scheme: "https"
    timeoutMs: 10000
```

### HTTP Content (`http.get`)

Performs a full GET — returns status, headers, and a body snippet (truncated to
5000 chars). Useful for probing exposure paths like `/.env`, `/.git/config`,
`/backup.zip`.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `path` | string | `/` | URL path to request |
| `scheme` | string | `https` | `http` or `https` |
| `timeoutMs` | number | `10000` | Request timeout |

```yaml
- name: Robots.txt
  uses: http.get
  with:
    path: "/robots.txt"
    scheme: "https"
    timeoutMs: 8000
```

### Security Header Score (`http.security_score`)

Scores the security-relevant response headers and assigns an **A–F** grade with
per-header presence, value, and remediation advice. Also flags version-banner info
leaks (`Server`, `X-Powered-By`). Headers evaluated (weighted): CSP, HSTS,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and
the Cross-Origin-Opener/Resource/Embedder-Policy family.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `path` | string | `/` | URL path to request |
| `scheme` | string | `https` | `http` or `https` |
| `timeoutMs` | number | `10000` | Request timeout |

```yaml
- name: Security Header Grade
  uses: http.security_score
  with:
    path: "/"
    scheme: "https"
    timeoutMs: 10000
```

### WAF / CDN Detection (`http.waf_detect`)

Detects WAF/CDN presence from response headers, cookies, and server banners.
Recognizes Cloudflare, AWS WAF/CloudFront, Akamai, Imperva/Incapsula, Sucuri,
F5 BIG-IP, Fastly, Varnish, Azure Front Door, Barracuda, and Wordfence — returning
each match with the evidence that triggered it.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `path` | string | `/` | URL path to request |
| `scheme` | string | `https` | `http` or `https` |
| `timeoutMs` | number | `10000` | Request timeout |

```yaml
- name: WAF Detection
  uses: http.waf_detect
  with:
    path: "/"
    scheme: "https"
```

### Technology Fingerprint (`http.fingerprint`)

Identifies the technology stack from response headers and (in deep mode) HTML body
markers — server, language, framework, CMS, analytics, and JS libraries. Each hit
records its category, name, source, and evidence.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `path` | string | `/` | URL path to request |
| `scheme` | string | `https` | `http` or `https` |
| `deep` | boolean | `true` | Also inspect the HTML body for client-side markers |
| `timeoutMs` | number | `10000` | Request timeout |

```yaml
- name: Tech Fingerprint
  uses: http.fingerprint
  with:
    path: "/"
    deep: true
```

### TLS Certificate (`tls.inspect`)

Inspects the TLS certificate and negotiated cipher — subject, SANs, issuer,
validity dates, fingerprint, cipher suite. Connects with validation disabled so it
can inspect invalid/self-signed certs; evaluate validity from the returned fields.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `port` | number | `443` | TLS port |
| `timeoutMs` | number | `12000` | Connect timeout |

```yaml
- name: TLS Certificate
  uses: tls.inspect
  with:
    port: 443
    timeoutMs: 10000
```

### Deep TLS Analysis (`tls.deep`)

Vulnerability-oriented TLS analysis — extends `tls.inspect` with a protocol
support matrix (flags deprecated TLS 1.0/1.1), weak-cipher probes (RC4/3DES/NULL),
certificate chain validation, OCSP stapling, and HSTS/preload status. Returns a
`findings` array with severities. **No API key.**

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `port` | number | `443` | TLS port |
| `timeoutMs` | number | `10000` | Per-probe timeout |

```yaml
- name: Deep TLS Analysis
  uses: tls.deep
  with:
    port: 443
    timeoutMs: 10000
```

> **Note:** weak-cipher and legacy-protocol detection depends on the local OpenSSL
> build. A server that *only* speaks fully-removed algorithms (e.g. raw RC4-MD5)
> may be unreachable from a modern OpenSSL 3 client; this is reported distinctly as
> "could not complete a TLS handshake" rather than a false negative.

---

## Available Playbooks

Production playbooks (each auto-registers as an MCP tool):

| Playbook | Focus |
| -------- | ----- |
| `quick-web-recon.md` | Fast essentials — DNS, HTTP, TLS, subdomains |
| `web-basic-recon.md` | Standard recon — DNS, WHOIS, port scan, basic HTTP |
| `comprehensive-web-recon.md` | Extensive recon with detailed DNS, security, and fingerprinting |
| `web-security-recon.md` | Vulnerability & information-disclosure focus |
| `api-cloud-recon.md` | APIs, microservices, and cloud platforms |
| `network-connectivity-test.md` | Liveness and network-path diagnostics |
| `email-security-assessment.md` | SPF · DMARC · DKIM · MTA-STS · BIMI |
| `tls-deep-assessment.md` | Protocols · weak ciphers · chain · OCSP · HSTS |
| `web-headers-assessment.md` | A–F security header grade · WAF/CDN · tech stack |

`all-tools-selftest.md` is a diagnostic playbook that exercises **every executor
exactly once** — useful for confirming the whole engine works end-to-end.

---

## Variable Templating

Use `{{vars.variableName}}` to substitute variables into any string option:

```yaml
vars:
  target: "example.com"
  scheme: "https"
  topPorts: 1000

steps:
  - name: Scan {{vars.target}}
    uses: nmap.scan
    with:
      flags: "--top-ports {{vars.topPorts}}"
```

A whole-string numeric template (e.g. `port: "{{vars.port}}"`) is coerced back to a
number automatically.

## Common Patterns

### Progressive Timeout Strategy

```yaml
vars:
  fastTimeout: 5000
  normalTimeout: 10000
  slowTimeout: 20000
```

### Conditional Scheme Detection

```yaml
- name: HTTPS Check
  uses: http.headers
  with:
    scheme: "https"
- name: HTTP Fallback
  uses: http.headers
  with:
    scheme: "http"
```

### Multi-Port TLS Analysis

```yaml
- name: HTTPS Certificate
  uses: tls.inspect
  with:
    port: 443
- name: Alternative HTTPS
  uses: tls.inspect
  with:
    port: 8443
```
