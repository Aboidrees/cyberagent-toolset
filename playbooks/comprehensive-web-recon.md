---
id: comprehensive-web-recon
title: Comprehensive Web Reconnaissance
vars:
  target: "example.com"
  scheme: "https"
  topPorts: 1000
  fullPorts: false
  deepScan: true
  timeout: 15000
steps:
  # DNS Intelligence Gathering
  - name: DNS A/AAAA Records
    uses: dns.resolve
    with:
      types: ["A", "AAAA"]
      timeoutMs: 5000
  - name: DNS CNAME/Alias Records
    uses: dns.resolve
    with:
      types: ["CNAME"]
      timeoutMs: 5000
  - name: DNS MX/Mail Records
    uses: dns.resolve
    with:
      types: ["MX"]
      timeoutMs: 5000
  - name: DNS NS/Nameserver Records
    uses: dns.resolve
    with:
      types: ["NS"]
      timeoutMs: 5000
  - name: DNS TXT Records (SPF/DKIM/DMARC)
    uses: dns.resolve
    with:
      types: ["TXT"]
      timeoutMs: 5000
  - name: DNS PTR/Reverse Records
    uses: dns.resolve
    with:
      types: ["PTR"]
      timeoutMs: 5000

  # WHOIS and Domain Intelligence
  - name: WHOIS Domain Registration Info
    uses: whois.lookup
    with:
      timeoutMs: 10000

  # Subdomain Discovery
  - name: Passive Subdomain Discovery (crt.sh)
    uses: subdomains.passive
    with:
      sources: ["crtsh"]
      timeoutMs: 20000

  # Port Scanning
  - name: Top Ports Scan (Fast)
    uses: nmap.scan
    with:
      flags: "-sT -T4 --top-ports {{vars.topPorts}}"
      timeoutMs: 30000
  - name: Common Web Ports Scan
    uses: nmap.scan
    with:
      flags: "-sT -T4 -p 80,443,8080,8443,8000,8888,3000,5000,9000"
      timeoutMs: 15000
  - name: Service Version Detection
    uses: nmap.scan
    with:
      flags: "-sV -Pn -p 80,443,8080,8443"
      timeoutMs: 25000

  # HTTP/HTTPS Analysis
  - name: HTTPS Headers Analysis
    uses: http.headers
    with:
      path: "/"
      scheme: "https"
      timeoutMs: "{{vars.timeout}}"
  - name: HTTP Headers Analysis (Fallback)
    uses: http.headers
    with:
      path: "/"
      scheme: "http"
      timeoutMs: "{{vars.timeout}}"
  - name: Security Headers Check
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      headers:
        User-Agent: "Mozilla/5.0 (compatible; ReconBot/1.0)"
      timeoutMs: "{{vars.timeout}}"

  # Common Web Files Discovery
  - name: robots.txt Discovery
    uses: http.get
    with:
      path: "/robots.txt"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: sitemap.xml Discovery
    uses: http.get
    with:
      path: "/sitemap.xml"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: humans.txt Discovery
    uses: http.get
    with:
      path: "/humans.txt"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: security.txt Discovery
    uses: http.get
    with:
      path: "/.well-known/security.txt"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: ads.txt Discovery
    uses: http.get
    with:
      path: "/ads.txt"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Admin/Config Files Discovery
  - name: Admin Panel Discovery
    uses: http.get
    with:
      path: "/admin"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: Login Page Discovery
    uses: http.get
    with:
      path: "/login"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: Config Files Discovery
    uses: http.get
    with:
      path: "/config"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: API Endpoints Discovery
    uses: http.get
    with:
      path: "/api"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: GraphQL Endpoint Discovery
    uses: http.get
    with:
      path: "/graphql"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Development/Debug Files
  - name: .env File Discovery
    uses: http.get
    with:
      path: "/.env"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: .git Directory Discovery
    uses: http.get
    with:
      path: "/.git/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: Backup Files Discovery
    uses: http.get
    with:
      path: "/backup"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: Debug Info Discovery
    uses: http.get
    with:
      path: "/debug"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # TLS/SSL Analysis
  - name: TLS Certificate Analysis (443)
    uses: tls.inspect
    with:
      port: 443
      timeoutMs: 10000
  - name: TLS Certificate Analysis (8443)
    uses: tls.inspect
    with:
      port: 8443
      timeoutMs: 10000

  # Technology Fingerprinting via Headers
  - name: Server Technology Headers
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      headers:
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        Accept-Language: "en-US,en;q=0.5"
        Accept-Encoding: "gzip, deflate"
        DNT: "1"
        Connection: "keep-alive"
        Upgrade-Insecure-Requests: "1"
      timeoutMs: "{{vars.timeout}}"

  # Error Page Analysis
  - name: 404 Error Page Analysis
    uses: http.get
    with:
      path: "/nonexistent-page-404-test"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: 403 Forbidden Analysis
    uses: http.get
    with:
      path: "/admin/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Common CMS/Framework Paths
  - name: WordPress Detection
    uses: http.get
    with:
      path: "/wp-admin/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: Drupal Detection
    uses: http.get
    with:
      path: "/user/login"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  - name: Joomla Detection
    uses: http.get
    with:
      path: "/administrator/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Cloud/CDN Detection
  - name: CloudFlare Detection
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      headers:
        CF-Connecting-IP: "test"
      timeoutMs: "{{vars.timeout}}"
---

## Comprehensive Web Reconnaissance for {{vars.target}}

This comprehensive playbook performs extensive web reconnaissance including:

### DNS Intelligence

- Complete DNS record enumeration (A, AAAA, CNAME, MX, NS, TXT, PTR)
- Domain registration information via WHOIS
- Passive subdomain discovery

### Network Analysis

- Port scanning (top ports + common web ports)
- Service version detection
- TLS/SSL certificate analysis

### Web Application Discovery

- HTTP/HTTPS headers analysis
- Security headers evaluation
- Common file discovery (robots.txt, sitemap.xml, etc.)
- Admin panel and API endpoint discovery
- Development/debug file detection

### Technology Fingerprinting

- Server technology identification
- CMS/Framework detection (WordPress, Drupal, Joomla)
- Cloud/CDN service detection
- Error page analysis

### Security Considerations

- This playbook is designed for authorized reconnaissance only
- Ensure you have permission to scan the target
- Some steps may trigger security alerts
- Use responsibly and in compliance with applicable laws

### Configuration

- `target`: Primary domain to scan
- `scheme`: http or https (default: https)
- `topPorts`: Number of top ports to scan (default: 1000)
- `timeout`: HTTP request timeout in ms (default: 15000)
- `deepScan`: Enable comprehensive scanning (default: true)

To run with custom target:

```bash
node ./src/index.js -p ./playbooks/comprehensive-web-recon.md --var target=yourdomain.com
```
