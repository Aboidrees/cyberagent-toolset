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
