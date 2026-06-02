# Executors

23 executors across 9 domain extensions, addressed by a stable `uses:` key.
Run `cats_capabilities` (MCP) for the live list. Full options + return shapes are
in the repo's `docs/executors.md`.

## Reconnaissance (passive — no packets to target)

| `uses` | Domain | What it does |
| ------ | ------ | ------------ |
| `dns.resolve` | dns | DNS records (A/AAAA/CNAME/NS/MX/TXT/PTR/SOA) |
| `dns.reverse` | dns | Reverse DNS / PTR lookup or CIDR sweep |
| `subdomains.passive` | dns | Passive subdomains via crt.sh |
| `whois.lookup` | whois | WHOIS registration data |
| `email.security` | email | SPF · DMARC · DKIM · MTA-STS · BIMI |
| `ip.intel` | ip-intel | ASN / BGP / country / hosting class (key-gated abuse score) |
| `shodan.host` | threat-intel | Shodan host data (requires `SHODAN_API_KEY`) |
| `vuln.cve_lookup` | threat-intel | NVD CVE lookup by product/keyword/CPE |

## Scanning (active)

| `uses` | Domain | What it does |
| ------ | ------ | ------------ |
| `network.ping` | network | ICMP ping statistics |
| `network.traceroute` | network | Hop-by-hop path |
| `nmap.scan` | network | nmap port/service scan |
| `http.headers` | web | Response headers |
| `http.get` | web | GET with body snippet |
| `http.security_score` | web | A–F security-header grade |
| `http.waf_detect` | web | WAF / CDN fingerprint |
| `http.fingerprint` | web | Technology stack |
| `http.cors_check` | web | CORS misconfiguration |
| `http.methods` | web | OPTIONS + risky-method probe |
| `tls.inspect` | tls | Certificate + cipher |
| `tls.deep` | tls | Protocols, weak ciphers, chain, OCSP, HSTS |

## Gaining Access (active — read-only exposure)

| `uses` | Domain | What it does |
| ------ | ------ | ------------ |
| `http.fuzz_paths` | web | Path enumeration (built-in wordlists) |
| `http.git_leak` | web | Exposed `.git` directory detector |
| `cloud.bucket_finder` | cloud | Public AWS S3 / GCP / Azure buckets |

## In a playbook

```yaml
steps:
  - name: Security Header Score
    uses: http.security_score
    with:
      path: "/"
      scheme: "https"
```

Each executor is also an MCP tool named `cats_<uses>` (dots → underscores), e.g.
`cats_http_security_score`. To add your own, see [[Extensions]].
