---
id: all-tools-selftest
title: All-Tools Self Test
vars:
  target: "fortmind.qa"
  scheme: "https"
  topPorts: 100
steps:
  - name: DNS records (A/AAAA/CNAME/NS/MX/TXT)
    uses: dns.resolve
    with:
      types: ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]
  - name: WHOIS
    uses: whois.lookup
  - name: Passive subdomains (crt.sh)
    uses: subdomains.passive
    with:
      sources: ["crtsh"]
  - name: Ping (liveness)
    uses: network.ping
    with:
      count: 4
  - name: Traceroute (network path)
    uses: network.traceroute
    with:
      maxHops: 15
  - name: Port scan (Nmap top ports)
    uses: nmap.scan
    with:
      flags: "-sT -Pn --top-ports {{vars.topPorts}}"
  - name: HTTP headers
    uses: http.headers
    with:
      path: "/"
      timeoutMs: 10000
  - name: HTTP GET (robots.txt)
    uses: http.get
    with:
      path: "/robots.txt"
      timeoutMs: 10000
  - name: TLS certificate info
    uses: tls.inspect
    with:
      port: 443
  - name: Reverse DNS / PTR
    uses: dns.reverse
  - name: Email security (SPF/DMARC/DKIM/MTA-STS/BIMI)
    uses: email.security
    with:
      timeoutMs: 20000
  - name: ASN / IP intelligence
    uses: ip.intel
  - name: Security header score (A–F)
    uses: http.security_score
    with:
      path: "/"
      timeoutMs: 10000
  - name: WAF / CDN fingerprint
    uses: http.waf_detect
    with:
      path: "/"
      timeoutMs: 10000
  - name: Technology fingerprint
    uses: http.fingerprint
    with:
      path: "/"
      deep: true
      timeoutMs: 10000
  - name: Deep TLS analysis
    uses: tls.deep
    with:
      port: 443
      timeoutMs: 10000
  - name: CVE lookup (NVD)
    uses: vuln.cve_lookup
    with:
      keyword: "OpenSSH 8.2"
      minCvss: 7.0
      maxResults: 5
  - name: Shodan host data
    uses: shodan.host
    with:
      timeoutMs: 15000
  - name: Cloud bucket discovery
    uses: cloud.bucket_finder
    with:
      timeoutMs: 30000        # step budget (per-probe is bounded internally)
  - name: Path discovery (fuzz)
    uses: http.fuzz_paths
    with:
      wordlist: "common"
      scheme: "{{vars.scheme}}"
      timeoutMs: 20000        # step budget (per-request is bounded internally)
  - name: Git repository leak
    uses: http.git_leak
    with:
      scheme: "{{vars.scheme}}"
      timeoutMs: 8000
  - name: CORS misconfiguration
    uses: http.cors_check
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: 10000
  - name: HTTP methods audit
    uses: http.methods
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: 15000        # step budget (per-request is bounded internally)
---

## All-tools self test against {{vars.target}}

A diagnostic playbook that exercises **every executor exactly once** — dns.resolve,
dns.reverse, whois.lookup, subdomains.passive, network.ping, network.traceroute,
nmap.scan, http.headers, http.get, http.security_score, http.waf_detect,
http.fingerprint, tls.inspect, tls.deep, email.security, ip.intel, vuln.cve_lookup,
shodan.host, cloud.bucket_finder, http.fuzz_paths, http.git_leak, http.cors_check,
http.methods — so you can confirm the whole engine works against a real target in
a single run.

WARNING: includes active steps (nmap.scan, ping, traceroute, path fuzzing). Run
only against targets you own or are authorized to scan. Requires `nmap` and
`traceroute` installed on the host. `shodan.host` is skipped unless
`SHODAN_API_KEY` is set.
