# Executors

Executors are the low-level modules that perform individual recon tasks. Each executor is used in playbooks via a `uses:` key and accepts options through the `with:` block.

---

## dns.resolve

Resolves DNS records for a target domain.

**Playbook key:** `dns.resolve`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `types` | string[] | `["A","AAAA"]` | Record types to query |
| `timeoutMs` | number | system default | Per-query timeout |

**Supported types:** `A`, `AAAA`, `CNAME`, `NS`, `MX`, `TXT`, `PTR`, `SOA`

```yaml
- name: Full DNS Sweep
  uses: dns.resolve
  with:
    types: ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]
    timeoutMs: 5000
```

**Returns:**

```json
{
  "A": ["104.26.14.170", "104.26.15.170"],
  "NS": ["hasslo.ns.cloudflare.com"],
  "MX": [{ "exchange": "aspmx.l.google.com", "priority": 1 }],
  "TXT": [["v=spf1 include:_spf.google.com -all"]],
  "SOA": { "nsname": "hasslo.ns.cloudflare.com", "serial": 2400801864 }
}
```

---

## whois.lookup

Performs a WHOIS lookup for a domain or IP address.

**Playbook key:** `whois.lookup`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `timeoutMs` | number | `15000` | Lookup timeout |

```yaml
- name: Domain Registration
  uses: whois.lookup
  with:
    timeoutMs: 15000
```

**Returns:** Full WHOIS record as a parsed object (registrar, dates, name servers, status, registrant).

---

## nmap.scan

Runs an nmap port scan against the target.

**Playbook key:** `nmap.scan`

**Requires:** `nmap` installed and in PATH.

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `flags` | string | `-sT -Pn --top-ports 1000` | nmap CLI flags |
| `timeoutMs` | number | `300000` (5 min) | Scan timeout |

```yaml
- name: Web Ports
  uses: nmap.scan
  with:
    flags: "-sT -Pn -p 80,443,8080,8443"
    timeoutMs: 30000
```

**Common flag combinations:**

| Goal | Flags |
| ------ | ------- |
| Top 1000 ports (default) | `-sT -Pn --top-ports 1000` |
| Top 100 ports (fast) | `-sT -Pn --top-ports 100` |
| Specific ports | `-sT -Pn -p 80,443,8080,8443` |
| Service versions | `-sT -sV -Pn --top-ports 100` |
| Fast + version | `-sT -sV -T4 --top-ports 100` |

> **Note:** Uses `-sT` (TCP connect) by default — does not require root privileges. Avoid `-sS` (SYN scan) unless running as root.

**Returns:**

```json
{
  "command": "nmap -sT -Pn --top-ports 1000 example.com",
  "raw": "Starting Nmap 7.94 ...\nPORT   STATE SERVICE\n80/tcp open  http\n443/tcp open  https\n",
  "target": "example.com",
  "flags": "-sT -Pn --top-ports 1000"
}
```

---

## http.headers

Fetches HTTP response headers for a given URL path.

**Playbook key:** `http.headers`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `path` | string | `/` | URL path |
| `scheme` | string | `https` | `http` or `https` |
| `timeoutMs` | number | `10000` | Request timeout |

```yaml
- name: Security Headers
  uses: http.headers
  with:
    path: "/"
    scheme: "https"
    timeoutMs: 10000
```

**Returns:**

```json
{
  "url": "https://example.com/",
  "status": 200,
  "headers": {
    "server": "cloudflare",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-frame-options": "SAMEORIGIN"
  }
}
```

---

## http.get

Performs a full HTTP GET and returns headers + a body snippet.

**Playbook key:** `http.get`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `path` | string | `/` | URL path |
| `scheme` | string | `https` | `http` or `https` |
| `timeoutMs` | number | `10000` | Request timeout |

```yaml
- name: Check for .env file
  uses: http.get
  with:
    path: "/.env"
    scheme: "https"
    timeoutMs: 8000
```

**Returns:**

```json
{
  "url": "https://example.com/.env",
  "status": 404,
  "headers": { "content-type": "text/html" },
  "bodySnippet": "<!DOCTYPE html>..."
}
```

Body is truncated to 5000 characters.

---

## tls.inspect

Inspects the TLS certificate and active cipher suite for a host.

**Playbook key:** `tls.inspect`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `port` | number | `443` | TLS port |
| `timeoutMs` | number | `12000` | Connection timeout |

```yaml
- name: TLS Certificate
  uses: tls.inspect
  with:
    port: 443
    timeoutMs: 12000
```

**Returns:**

```json
{
  "servername": "example.com",
  "port": 443,
  "cipher": {
    "name": "TLS_AES_256_GCM_SHA384",
    "version": "TLSv1.3"
  },
  "cert": {
    "subject": { "CN": "example.com" },
    "issuer": { "O": "Let's Encrypt", "CN": "R3" },
    "valid_from": "Jan  1 00:00:00 2026 GMT",
    "valid_to":   "Apr  1 00:00:00 2026 GMT",
    "altNames": "DNS:example.com, DNS:*.example.com",
    "fingerprint256": "AA:BB:CC:..."
  }
}
```

> `rejectUnauthorized` is `false` intentionally — this allows inspection of self-signed and expired certificates. Evaluate validity from the returned `valid_to` and `issuer` fields.

---

## subdomains.passive

Passively enumerates subdomains via certificate transparency logs (crt.sh). No active probing.

**Playbook key:** `subdomains.passive`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `sources` | string[] | `["crtsh"]` | Data sources to query |
| `timeoutMs` | number | `20000` | Request timeout |

```yaml
- name: Subdomain Discovery
  uses: subdomains.passive
  with:
    sources: ["crtsh"]
    timeoutMs: 20000
```

**Returns:**

```json
{
  "merged": ["api.example.com", "mail.example.com", "vpn.example.com"],
  "sources": {
    "crtsh": ["api.example.com", "mail.example.com", "vpn.example.com"]
  }
}
```

---

## network.ping

Sends ICMP pings and returns latency statistics.

**Playbook key:** `network.ping`

**Requires:** `ping` in PATH (pre-installed everywhere).

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `count` | number | `4` | Number of packets |
| `timeoutMs` | number | `30000` | Overall timeout |

```yaml
- name: Ping Test
  uses: network.ping
  with:
    count: 4
    timeoutMs: 10000
```

**Returns:**

```json
{
  "command": "ping -c 4 example.com",
  "target": "example.com",
  "stats": {
    "packetsTransmitted": 4,
    "packetsReceived": 4,
    "packetLoss": 0,
    "minTime": 12.3,
    "avgTime": 14.1,
    "maxTime": 16.7
  }
}
```

---

## network.traceroute

Traces the network path hop-by-hop to the target.

**Playbook key:** `network.traceroute`

**Requires:** `traceroute` (Unix/macOS) or `tracert` (Windows) in PATH.

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `maxHops` | number | `30` | Maximum hop count |
| `timeoutMs` | number | `60000` | Overall timeout |

```yaml
- name: Network Path
  uses: network.traceroute
  with:
    maxHops: 20
    timeoutMs: 45000
```

**Returns:**

```json
{
  "command": "traceroute -m 20 -n example.com",
  "target": "example.com",
  "hopCount": 12,
  "hops": [
    { "number": 1, "ip": "192.168.1.1", "times": [0.4, 0.5, 0.4] },
    { "number": 2, "ip": "10.0.0.1",   "times": [1.2, 1.1, 1.3] }
  ]
}
```

Hops with `timeout: true` indicate filtered or unreachable nodes (`* * *`).

---

## dns.reverse

Reverse DNS (PTR) lookup or sweep. Accepts a single IP, an IPv4 CIDR range (sweeps every host), or a hostname (resolves A/AAAA first, then reverses each address).

**Playbook key:** `dns.reverse`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `maxHosts` | number | `256` | Upper bound on addresses for a CIDR sweep |

```yaml
- name: PTR Sweep
  uses: dns.reverse
  with:
    maxHosts: 256
```

**Returns:**

```json
{
  "target": "1.1.1.1",
  "resolvedFrom": "ip",
  "ipCount": 1,
  "ptr": { "1.1.1.1": ["one.one.one.one"] },
  "names": ["one.one.one.one"]
}
```

---

## email.security

Evaluates a domain's email authentication posture — SPF, DMARC, DKIM, MTA-STS, BIMI. Passive DNS lookups plus one HTTPS fetch for the MTA-STS policy file. No API key required.

**Playbook key:** `email.security`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `selectors` | string[] | common set | DKIM selectors to probe |
| `timeoutMs` | number | `8000` | MTA-STS policy fetch timeout |
| `dnsTimeoutMs` | number | `6000` | Per-DNS-lookup cap (all lookups run concurrently) |

```yaml
- name: Email Security
  uses: email.security
  with:
    selectors: ["default", "google", "selector1", "selector2"]
```

**Returns:** Per-check objects (`spf`, `dmarc`, `dkim`, `mtaSts`, `bimi`) each with a `findings` array, plus a top-level `summary` and a rolled-up `findings` list. Severities flag spoofing-enabling misconfigs (missing SPF/DMARC, `p=none`, `+all`, etc.).

---

## ip.intel

ASN / IP intelligence via Team Cymru's keyless DNS service: ASN, BGP prefix, country, registry, allocation date, and hosting/CDN classification. Abuse reputation (AbuseIPDB) is an **optional, key-gated** enrichment — it runs only when `ABUSEIPDB_API_KEY` (env) or `opts.apiKey` is supplied, and is otherwise skipped with a note.

**Playbook key:** `ip.intel`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `ip` | string | resolved from target | Explicit IP to analyse instead of resolving the target |
| `apiKey` | string | `ABUSEIPDB_API_KEY` env | Enables AbuseIPDB reputation (optional) |

```yaml
- name: IP Intelligence
  uses: ip.intel
  with:
    ip: "104.26.14.170"
```

**Returns:**

```json
{
  "target": "cloudflare.com",
  "ip": "104.16.132.229",
  "asn": { "asn": "13335", "bgpPrefix": "104.16.128.0/20", "country": "US", "asName": "CLOUDFLARENET, US" },
  "hosting": { "provider": "Cloudflare", "type": "cdn" },
  "reputation": { "checked": false, "note": "Skipped — set ABUSEIPDB_API_KEY to enable abuse-reputation scoring." }
}
```

---

## http.security_score

Scores the security-relevant response headers and assigns an A–F letter grade with per-header presence, value, and remediation advice. Also flags version-banner info leaks (`Server`, `X-Powered-By`).

**Playbook key:** `http.security_score`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `path` | string | `/` | URL path |
| `scheme` | string | `https` | `http` or `https` |
| `timeoutMs` | number | `10000` | Request timeout |

Headers evaluated (weighted): `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener/Resource/Embedder-Policy`.

```yaml
- name: Security Header Score
  uses: http.security_score
  with:
    path: "/"
```

**Returns:** `{ grade, score, earned, maxScore, presentCount, missing, infoLeaks, details }`.

---

## http.waf_detect

Detects WAF / CDN presence from response headers, cookies, and server banners.

**Playbook key:** `http.waf_detect`

Detects: Cloudflare, AWS WAF/CloudFront, Akamai, Imperva/Incapsula, Sucuri, F5 BIG-IP, Fastly, Varnish, Azure Front Door, Barracuda, Wordfence.

```yaml
- name: WAF Detection
  uses: http.waf_detect
```

**Returns:** `{ url, status, wafDetected, detected: [{ name, type, evidence }], server }`.

---

## http.fingerprint

Identifies the technology stack from response headers and (in deep mode) HTML body markers — server, language, framework, CMS, analytics, and JS libraries.

**Playbook key:** `http.fingerprint`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `path` | string | `/` | URL path |
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

**Returns:** `{ url, status, server, poweredBy, technologies: [{ category, name, source, evidence }] }`.

---

## tls.deep

Vulnerability-oriented TLS analysis — extends `tls.inspect` with a protocol support matrix (flags deprecated TLS 1.0/1.1), weak-cipher probes (RC4/3DES/NULL), certificate chain validation, OCSP stapling, and HSTS/preload status. Keyless.

**Playbook key:** `tls.deep`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `port` | number | `443` | TLS port |
| `timeoutMs` | number | `10000` | Per-probe timeout |

```yaml
- name: Deep TLS Analysis
  uses: tls.deep
  with:
    port: 443
```

**Returns:** `{ protocols, weakCiphers, chain, ocspStapling, hsts, findings }`.

> **Note:** weak-cipher and legacy-protocol detection depends on the local OpenSSL build. A server that *only* speaks fully-removed algorithms (e.g. raw RC4-MD5) may be unreachable from a modern OpenSSL 3 client; this is reported distinctly as "could not complete a TLS handshake" rather than a false negative.

---

## vuln.cve_lookup

CVE lookup against the National Vulnerability Database (NVD API v2). Matches by product/version, not by host — typically driven by what a version scan (`nmap.scan -sV`) discovered. Keyless; set `NVD_API_KEY` to raise the rate limit.

**Playbook key:** `vuln.cve_lookup`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `keyword` | string | — | Free-text search, e.g. `"Apache httpd 2.4.49"` |
| `cpe` | string | — | Exact CPE 2.3 name (alternative to keyword) |
| `product` | string | — | Product name (combined with `version`) |
| `version` | string | — | Product version |
| `minCvss` | number | `0` | Minimum CVSS base score to include |
| `severity` | string | — | Filter by CVSS v3 severity: LOW/MEDIUM/HIGH/CRITICAL |
| `maxResults` | number | `20` | Max CVEs to return (cap 100) |
| `apiKey` | string | `NVD_API_KEY` env | NVD API key for higher rate limits (optional) |

```yaml
- name: CVE Lookup
  uses: vuln.cve_lookup
  with:
    keyword: "Apache httpd 2.4.49"
    minCvss: 7.0
```

**Returns:** `{ query, totalMatched, returned, severityCounts, results: [{ id, cvss, severity, vector, description, url }] }` sorted by CVSS descending.

---

## shodan.host

Shodan host lookup — open ports, services, banners, CVEs, and tags from Shodan's index. **Requires** a Shodan API key (`SHODAN_API_KEY` env or `apiKey`); returns a no-op note when no key is set, so it never fails a run.

**Playbook key:** `shodan.host`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `apiKey` | string | `SHODAN_API_KEY` env | Shodan API key (required to run) |
| `timeoutMs` | number | `15000` | Request timeout |

```yaml
- name: Shodan Host Data
  uses: shodan.host
```

**Returns:** `{ target, ip, checked, found, org, ports, hostnames, tags, vulns, services }` — or `{ checked: false, note }` when no key is set.

---

## cloud.bucket_finder

Cloud storage bucket finder — derives candidate bucket names from the target domain and probes AWS S3, GCP Cloud Storage, and Azure Blob endpoints for public exposure. Read-only GET probes; no credentials, no API key.

**Playbook key:** `cloud.bucket_finder`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `extraNames` | string[] | `[]` | Additional candidate bucket names |
| `concurrency` | number | `12` | Parallel probes (cap 32) |
| `requestTimeoutMs` | number | `6000` | Per-probe timeout |
| `timeoutMs` | number | step budget | Overall step budget (per-probe is bounded by `requestTimeoutMs`) |

```yaml
- name: Cloud Bucket Discovery
  uses: cloud.bucket_finder
```

**Returns:** `{ target, candidatesTried, probesRun, found, exposed, findings: [{ name, provider, url, status, exists, access, severity }] }`. `public`/`public-listable` access is high severity; `private` (403) means the bucket exists but is locked down.

---

## http.fuzz_paths

Active path enumeration against a built-in wordlist (`common`, `api`, `admin`, `php`, `asp`) or a custom array. Reports paths that exist by status code (anything that isn't a hard 404 / connection error). Concurrency-bounded. **Active — authorized targets only.**

**Playbook key:** `http.fuzz_paths`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `wordlist` | string \| string[] | `common` | Built-in name or a custom array of paths |
| `scheme` | string | `https` | `http` or `https` |
| `threads` | number | `10` | Concurrency (cap 32) |
| `requestTimeoutMs` | number | `5000` | Per-request timeout |
| `timeoutMs` | number | step budget | Overall step budget (the runner caps the whole step; per-request is bounded by `requestTimeoutMs`) |

```yaml
- name: Path Discovery
  uses: http.fuzz_paths
  with:
    wordlist: "common"
```

**Returns:** `{ target, wordlist, pathsTried, found, hits: [{ path, status, contentLength }] }`.

---

## http.git_leak

Git repository leak detector — checks for an exposed `.git/` directory, validates that `/.git/HEAD` is a real git ref (not a catch-all page), then pulls indicators (remote origin URL, last commit message) from `/.git/config` and `/.git/COMMIT_EDITMSG`. Flags **critical** when reachable.

**Playbook key:** `http.git_leak`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `scheme` | string | `https` | `http` or `https` |
| `timeoutMs` | number | `8000` | Per-request timeout |

```yaml
- name: Git Repository Leak
  uses: http.git_leak
```

**Returns:** `{ target, exposed, severity, checks, indicators: { remoteOrigin, lastCommitMessage }, note }`.

---

## http.cors_check

CORS misconfiguration probe — sends a hostile `Origin` and inspects the `Access-Control-Allow-Origin` / `-Credentials` response. Flags origin reflection and the wildcard-plus-credentials combination.

**Playbook key:** `http.cors_check`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `path` | string | `/` | URL path |
| `scheme` | string | `https` | `http` or `https` |
| `origin` | string | `https://evil.example.com` | Hostile Origin to test |
| `timeoutMs` | number | `10000` | Request timeout |

```yaml
- name: CORS Misconfiguration
  uses: http.cors_check
  with:
    path: "/api/"
```

**Returns:** `{ url, status, testedOrigin, allowOrigin, allowCredentials, reflectsOrigin, misconfigured, findings }`.

---

## http.methods

HTTP methods audit — reads the `OPTIONS` `Allow` header and actively probes risky methods (PUT/DELETE/TRACE/PATCH) concurrently. Flags TRACE (Cross-Site Tracing) and accepted write methods. (CONNECT is intentionally excluded — Node treats it as a tunnel request that never returns a normal response.)

**Playbook key:** `http.methods`

| Option | Type | Default | Description |
| -------- | ------ | --------- | ------------- |
| `path` | string | `/` | URL path |
| `scheme` | string | `https` | `http` or `https` |
| `requestTimeoutMs` | number | `6000` | Per-request timeout |
| `timeoutMs` | number | step budget | Overall step budget (per-request is bounded by `requestTimeoutMs`) |

```yaml
- name: HTTP Methods Audit
  uses: http.methods
```

**Returns:** `{ url, advertised, riskyAccepted: [{ method, status }], findings }`.

---

## Expanded toolset (Phase 4+)

The following executors were added across the Phase 4–7 expansions. Keyless unless noted.

### DNS

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `dns.dnssec` | recon · passive | `timeoutMs` | `{ enabled, hasDnskey, hasDs, authenticated, findings }` — DNSSEC posture via DNS-over-HTTPS |
| `dns.caa` | recon · passive | `timeoutMs` | `{ records, issuers, findings }` — CAA issuance policy |
| `subdomains.bruteforce` | recon · active | `wordlist[]`, `concurrency`, `lookupTimeoutMs` | `{ wordsTried, found, subdomains[] }` — active subdomain brute-force |
| `dns.txt_fingerprint` | recon · passive | `timeoutMs` | `{ txtRecordCount, servicesFound, services[] }` — SaaS/vendor footprint from TXT domain-verification tokens (Google, M365, Atlassian, Stripe, …) via DNS-over-HTTPS |
| `dns.zone_transfer` | recon · active | `timeoutMs` | `{ nameservers[], vulnerable, results[], findings }` — attempts AXFR against each authoritative NS; **critical** finding if any server allows the transfer (full-zone disclosure) |

### Web

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `http.cookies` | scanning · active | `path`, `scheme` | Cookie `Secure`/`HttpOnly`/`SameSite` audit + findings |
| `http.robots` | recon · active | `scheme` | robots.txt `Disallow` + sitemap URLs |
| `http.secrets` | gaining-access · active | `path`, `scheme` | Regex scan of the body for exposed keys/tokens/private keys + findings |
| `http.open_redirect` | scanning · active | `path`, `scheme`, `params[]` | Open-redirect probe across common params + findings |
| `http.subdomain_takeover` | scanning · active | `scheme` | Dangling-CNAME takeover detection (GitHub/S3/Heroku/Azure/Fastly/…) |
| `http.graphql` | scanning · active | `path`, `scheme` | `{ pathsTried, endpoints[], introspectionExposed, findings }` — probes common GraphQL paths and flags exposed introspection |
| `web.security_txt` | recon · active | `scheme`, `timeoutMs` | `{ found, contact[], policy[], expires, fields, findings }` — parses security.txt (RFC 9116); flags an expired policy |
| `web.well_known` | recon · active | `scheme`, `timeoutMs` | `{ probed, presentCount, endpoints[], findings }` — enumerates well-known URIs (OAuth/OpenID discovery, MTA-STS, change-password, app-association) |
| `http.favicon_hash` | recon · active | `path`, `scheme`, `timeoutMs` | `{ found, bytes, hash, shodanQuery }` — Shodan/Censys favicon hash (mmh3) for pivoting to related infrastructure |
| `web.screenshot` | scanning · active | `scheme`, `path`, `width`, `height`, `outFile`, `waitMs` | `{ captured, browser, file, bytes, dimensions }` — headless-browser PNG capture. No-op note without a Chrome/Chromium binary (set `CHROME_PATH` to override) |
| `web.wayback` | recon · passive | `limit` | Archived URLs from the Wayback Machine (queries archive.org, not the target) |

### Registration & certificates

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `rdap.lookup` | recon · passive | `timeoutMs` | `{ kind, registrar, status[], events, nameservers[], abuseContact, dnssec, findings }` — structured WHOIS over RDAP/HTTPS (RFC 9083) for a domain or IP; flags near/expired domains |
| `cert.ctlog` | recon · passive | `limit`, `includeSubdomains`, `timeoutMs` | `{ totalCertificates, uniqueNames, issuers[], firstSeen, lastExpiry, certificates[], findings }` — Certificate Transparency history via crt.sh |

### Email — SMTP

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `smtp.probe` | scanning · active | `port`, `mx`, `relayTest`, `timeoutMs` | `{ mx, banner, starttls, authMechanisms[], findings }` — SMTP EHLO probe: STARTTLS support, AUTH mechanisms, cleartext-auth flag; optional read-only open-relay heuristic (aborts before DATA) |

### SSH

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `ssh.audit` | scanning · active | `port`, `timeoutMs` | `{ banner, kexAlgorithms[], hostKeyAlgorithms[], ciphers[], macs[], weak{}, findings }` — parses the SSH banner + KEXINIT and flags weak/deprecated cipher/KEX/MAC/host-key algorithms (no auth) |

### SMB

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `smb.probe` | scanning · active | `port`, `timeoutMs` | `{ dialect, signingEnabled, signingRequired, findings }` — SMB2 NEGOTIATE over TCP/445; flags signing-not-required (NTLM-relay exposure). No authentication |

### SNMP

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `snmp.probe` | scanning · active | `port`, `communities[]`, `timeoutMs` | `{ communitiesTried, open[], sysDescr, exposed, findings }` — read-only SNMPv2c GET (sysDescr) per candidate community; flags agents answering a default/guessable community |

### Database & remote services

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `mysql.probe` | scanning · active | `port`, `timeoutMs` | `{ isMySQL, protocol, serverVersion, findings }` — reads the MySQL/MariaDB handshake (version banner). No auth |
| `postgres.probe` | scanning · active | `port`, `timeoutMs` | `{ isPostgres, sslSupported, findings }` — PostgreSQL SSLRequest fingerprint + TLS availability. No auth |
| `rdp.probe` | scanning · active | `port`, `timeoutMs` | `{ isRDP, security, nla, findings }` — RDP X.224 negotiation; flags Standard Security (no TLS/NLA). No credentials |
| `ldap.probe` | scanning · active | `port`, `timeoutMs` | `{ isLDAP, anonymousBind, result, findings }` — LDAP anonymous simple-bind check (directory-enumeration exposure). Read-only |

### Auth-aware scanning

All `http.*` executors accept auth options to reach content behind a login:
`bearer` (→ `Authorization: Bearer`), `basic` (`"user:pass"` → `Authorization: Basic`),
`cookie` (session cookie value), and `headers` (arbitrary extra headers).

```yaml
- name: Authenticated header grade
  uses: http.security_score
  with:
    bearer: "{{env.API_TOKEN}}"
    cookie: "session=abc123"
```

### Cloud

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `cloud.bucket_objects` | gaining-access · active | `url` \| `bucket`+`provider`, `container`, `limit`, `timeoutMs` | `{ listable, objectCount, truncated, objects[], sensitive[], findings }` — lists a public-listable bucket (S3/GCS/Azure) and flags sensitive keys (backups, dumps, secrets) |

### Network

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `nmap.udp` | scanning · active | `flags`, `timeoutMs` | UDP scan (`-sU`). No-op note without root |
| `nmap.os` | scanning · active | `timeoutMs` | OS fingerprint (`-O`). No-op note without root |
| `network.banner` | scanning · active | `ports[]`, `requestTimeoutMs` | TCP service banner grab (SSH/FTP/SMTP/Redis/…) |

### Vulnerability — Nuclei (the multiplier)

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `nuclei.scan` | scanning · active | `scheme`, `severity`, `tags`, `templates[]` | Runs the `nuclei` binary (thousands of templates) → severity-rated findings. No-op note if the binary is absent. Install: github.com/projectdiscovery/nuclei |

### Threat intel — keyless

| `uses` | Phase · Posture | Options | Returns |
| ------ | --------------- | ------- | ------- |
| `vuln.epss` | recon · passive | `cve` (id or comma list), `minScore`, `findingThreshold`, `timeoutMs` | `{ query, returned, results[], findings }` — EPSS exploit-probability (FIRST.org) for one or more CVEs; flags high-probability CVEs. Pair with `vuln.cve_lookup` to prioritise by real-world risk, not just CVSS |

### Threat intel — key-gated (no-op without keys)

| `uses` | Key | Returns |
| ------ | --- | ------- |
| `hunter.emails` | `HUNTER_API_KEY` | Hunter.io domain email harvest — addresses, pattern, organization |
| `securitytrails.subdomains` | `SECURITYTRAILS_API_KEY` | Historical subdomains |
| `securitytrails.dns_history` | `SECURITYTRAILS_API_KEY` | Historical A-record timeline |
| `censys.host` | `CENSYS_API_ID` + `CENSYS_API_SECRET` | Host services/software/ASN/location |
| `github.leaks` | `GITHUB_TOKEN` | Public GitHub code referencing the domain + findings |
