---
id: web-basic-recon
title: Basic Web Recon
vars:
  target: "example.com"
  scheme: "https"
  topPorts: 1000
steps:
  - name: Resolve DNS A/AAAA
    uses: dns.resolve
    with:
      types: ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]
  - name: WHOIS
    uses: whois.lookup
  - name: Port scan (Nmap top ports)
    uses: nmap.scan
    with:
      flags: "-sV -Pn --top-ports {{vars.topPorts}}"
  - name: HTTP headers
    uses: http.headers
    with:
      path: "/"
      timeoutMs: 10000
  - name: robots.txt
    uses: http.get
    with:
      path: "/robots.txt"
      timeoutMs: 10000
  - name: TLS certificate info
    uses: tls.inspect
    with:
      port: 443
  - name: Passive subdomains (crt.sh)
    uses: subdomains.passive
    with:
      sources: ["crtsh"]
...
# Basic web recon against {{vars.target}}

This playbook performs DNS/WHOIS, top-ports scan, basic HTTP checks, TLS metadata, and passive subdomain discovery (no active brute-force).