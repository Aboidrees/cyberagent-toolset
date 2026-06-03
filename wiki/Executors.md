# Executors

40 executors across 13 domain extensions, addressed by a stable `uses:` key. Run
`cats_capabilities` (MCP) for the live list. Full options + return shapes are in
the repo's `docs/executors.md`.

## Reconnaissance (passive — no packets to the target host)

| `uses` | Domain | What it does |
| ------ | ------ | ------------ |
| `dns.resolve` | dns | DNS records (A/AAAA/CNAME/NS/MX/TXT/PTR/SOA) |
| `dns.reverse` | dns | Reverse DNS / PTR lookup or CIDR sweep |
| `dns.dnssec` | dns | DNSSEC posture (DNSKEY/DS + AD flag) via DoH |
| `dns.caa` | dns | CAA records — which CAs may issue certs |
| `subdomains.passive` | dns | Passive subdomains via crt.sh |
| `whois.lookup` | whois | WHOIS registration data |
| `email.security` | email | SPF · DMARC · DKIM · MTA-STS · BIMI |
| `ip.intel` | ip-intel | ASN / BGP / country / hosting (key-gated abuse score) |
| `shodan.host` | threat-intel | Shodan host data (needs `SHODAN_API_KEY`) |
| `vuln.cve_lookup` | threat-intel | NVD CVE lookup by product/keyword/CPE |
| `web.wayback` | web | Archived URLs from the Wayback Machine |
| `securitytrails.subdomains` | securitytrails | Historical subdomains (needs key) |
| `securitytrails.dns_history` | securitytrails | Historical A-record timeline (needs key) |
| `censys.host` | censys | Host services/software/ASN (needs key) |
| `github.leaks` | github-leaks | Public code referencing the domain (needs `GITHUB_TOKEN`) |

## Reconnaissance / Scanning (active)

| `uses` | Domain | What it does |
| ------ | ------ | ------------ |
| `subdomains.bruteforce` | dns | Active subdomain brute-force (built-in wordlist) |
| `http.robots` | web | robots.txt + sitemap endpoint discovery |
| `network.ping` | network | ICMP ping statistics |
| `network.traceroute` | network | Hop-by-hop path |
| `nmap.scan` | network | nmap TCP port/service scan |
| `nmap.udp` | network | nmap UDP scan (no-op without root) |
| `nmap.os` | network | nmap OS fingerprint (no-op without root) |
| `network.banner` | network | TCP service banner grab |
| `http.headers` | web | Response headers |
| `http.get` | web | GET with body snippet |
| `http.security_score` | web | A–F security-header grade |
| `http.waf_detect` | web | WAF / CDN fingerprint |
| `http.fingerprint` | web | Technology stack |
| `http.cors_check` | web | CORS misconfiguration |
| `http.methods` | web | OPTIONS + risky-method probe |
| `http.cookies` | web | Cookie Secure/HttpOnly/SameSite audit |
| `http.open_redirect` | web | Open-redirect probe |
| `http.subdomain_takeover` | web | Dangling-CNAME takeover detection |
| `tls.inspect` | tls | Certificate + cipher |
| `tls.deep` | tls | Protocols, weak ciphers, chain, OCSP, HSTS |
| `nuclei.scan` | nuclei | **Nuclei templates — thousands of checks** (needs the `nuclei` binary) |

## Gaining Access (active — read-only exposure)

| `uses` | Domain | What it does |
| ------ | ------ | ------------ |
| `http.fuzz_paths` | web | Path enumeration (built-in wordlists) |
| `http.git_leak` | web | Exposed `.git` directory detector |
| `http.secrets` | web | Scan response body for exposed keys/tokens |
| `cloud.bucket_finder` | cloud | Public AWS S3 / GCP / Azure buckets |

## In a playbook

```yaml
steps:
  - name: Nuclei
    uses: nuclei.scan
    with:
      severity: critical,high
      tags: cves,exposures
```

Each executor is also an MCP tool named `cats_<uses>` (dots → underscores). Add
your own via [[Extensions]]. Key-gated tools no-op with a note until their key is
set — see [[API Keys]].
