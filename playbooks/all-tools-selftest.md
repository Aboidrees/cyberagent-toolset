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
---

## All-tools self test against {{vars.target}}

A diagnostic playbook that exercises **every executor exactly once** — dns.resolve,
dns.reverse, whois.lookup, subdomains.passive, network.ping, network.traceroute,
nmap.scan, http.headers, http.get, http.security_score, http.waf_detect,
http.fingerprint, tls.inspect, tls.deep, email.security, ip.intel — so you can
confirm the whole engine works against a real target in a single run.

WARNING: includes active steps (nmap.scan, ping, traceroute). Run only against
targets you own or are authorized to scan. Requires `nmap` and `traceroute`
installed on the host.
