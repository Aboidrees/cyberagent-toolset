# Executors

56 executors across 18 domain extensions, addressed by a stable `uses:` key. Run
`cats_capabilities` (MCP) for the live list. Full options + return shapes are in
the repo's `docs/executors.md`.

## Reconnaissance (passive — no packets to the target host)

| `uses` | Domain | What it does |
| ------ | ------ | ------------ |
| `dns.resolve` | dns | DNS records (A/AAAA/CNAME/NS/MX/TXT/PTR/SOA) |
| `dns.reverse` | dns | Reverse DNS / PTR lookup or CIDR sweep |
| `dns.dnssec` | dns | DNSSEC posture (DNSKEY/DS + AD flag) via DoH |
| `dns.caa` | dns | CAA records — which CAs may issue certs |
| `dns.txt_fingerprint` | dns | SaaS/vendor footprint from TXT verification tokens (via DoH) |
| `subdomains.passive` | dns | Passive subdomains via crt.sh |
| `whois.lookup` | whois | WHOIS registration data |
| `rdap.lookup` | rdap | Structured WHOIS over RDAP/HTTPS (domains + IPs) |
| `cert.ctlog` | tls | Certificate Transparency history via crt.sh (issuers, timeline, names) |
| `email.security` | email | SPF · DMARC · DKIM · MTA-STS · BIMI |
| `ip.intel` | ip-intel | ASN / BGP / country / hosting (key-gated abuse score) |
| `shodan.host` | threat-intel | Shodan host data (needs `SHODAN_API_KEY`) |
| `vuln.cve_lookup` | threat-intel | NVD CVE lookup by product/keyword/CPE |
| `vuln.epss` | threat-intel | EPSS exploit-probability scoring for CVEs (FIRST.org) |
| `web.wayback` | web | Archived URLs from the Wayback Machine |
| `securitytrails.subdomains` | securitytrails | Historical subdomains (needs key) |
| `securitytrails.dns_history` | securitytrails | Historical A-record timeline (needs key) |
| `censys.host` | censys | Host services/software/ASN (needs key) |
| `github.leaks` | github-leaks | Public code referencing the domain (needs `GITHUB_TOKEN`) |
| `hunter.emails` | hunter | Hunter.io domain email harvest — addresses + pattern (needs `HUNTER_API_KEY`) |

## Reconnaissance / Scanning (active)

| `uses` | Domain | What it does |
| ------ | ------ | ------------ |
| `subdomains.bruteforce` | dns | Active subdomain brute-force (built-in wordlist) |
| `dns.zone_transfer` | dns | AXFR zone-transfer attempt per NS (critical if allowed) |
| `http.robots` | web | robots.txt + sitemap endpoint discovery |
| `web.security_txt` | web | security.txt (RFC 9116) disclosure contact/policy |
| `web.well_known` | web | Well-known URIs (OAuth/OpenID discovery, MTA-STS, policies) |
| `http.favicon_hash` | web | Shodan/Censys favicon hash (mmh3) for infra correlation |
| `smtp.probe` | email | SMTP EHLO — STARTTLS/AUTH + optional open-relay heuristic |
| `ssh.audit` | ssh | SSH KEXINIT weak cipher/KEX/MAC/host-key audit |
| `smb.probe` | smb | SMB2 NEGOTIATE — dialect + signing-required (NTLM-relay) check |
| `snmp.probe` | snmp | SNMPv2c community-string probe (public/private/…) |
| `web.screenshot` | web | Headless-browser PNG screenshot (no-op without Chrome/Chromium) |
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
| `http.graphql` | web | GraphQL endpoint discovery + introspection exposure |
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
| `cloud.bucket_objects` | cloud | List objects in a public bucket; flags sensitive keys |

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
