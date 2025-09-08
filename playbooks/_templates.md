---
id: <unique-id>
title: <human title>
vars:
  target: "example.com"
  scheme: "https"
  timeout: 10000
steps:
  - name: <step name>
    uses: dns.resolve|whois.lookup|nmap.scan|http.headers|http.get|tls.inspect|subdomains.passive
    with: { ... executor-specific options ... }
---

## Playbook Templates and Examples

This file contains templates and examples for creating reconnaissance playbooks.

### Available Executors

#### DNS Resolution (`dns.resolve`)

```yaml
- name: DNS Records
  uses: dns.resolve
  with:
    types: ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "PTR"]
    timeoutMs: 5000
```

#### WHOIS Lookup (`whois.lookup`)

```yaml
- name: Domain Information
  uses: whois.lookup
  with:
    timeoutMs: 10000
```

#### Port Scanning (`nmap.scan`)

```yaml
- name: Port Scan
  uses: nmap.scan
  with:
    flags: "-sS -T4 --top-ports 1000"
    timeoutMs: 30000
```

#### HTTP Headers (`http.headers`)

```yaml
- name: HTTP Headers
  uses: http.headers
  with:
    path: "/"
    scheme: "https"
    headers:
      User-Agent: "Custom-Agent/1.0"
    timeoutMs: 10000
```

### HTTP Content (`http.get`)

```yaml
- name: Robots.txt
  uses: http.get
  with:
    path: "/robots.txt"
    scheme: "https"
    timeoutMs: 8000
```

### TLS Certificate (`tls.inspect`)

```yaml
- name: TLS Certificate
  uses: tls.inspect
  with:
    port: 443
    timeoutMs: 10000
```

### Subdomain Discovery (`subdomains.passive`)

```yaml
- name: Passive Subdomains
  uses: subdomains.passive
  with:
    sources: ["crtsh"]
    timeoutMs: 15000
```

## Available Playbooks

### 1. Basic Web Reconnaissance (`web-basic-recon.md`)

Standard reconnaissance including DNS, WHOIS, port scanning, and basic HTTP checks.

### 2. Comprehensive Web Reconnaissance (`comprehensive-web-recon.md`)

Extensive reconnaissance with detailed DNS analysis, security checks, and technology fingerprinting.

### 3. Security-Focused Reconnaissance (`web-security-recon.md`)

Specialized security assessment focusing on vulnerabilities and information disclosure.

### 4. API and Cloud Service Reconnaissance (`api-cloud-recon.md`)

Modern application reconnaissance targeting APIs, microservices, and cloud platforms.

### 5. Quick Web Reconnaissance (`quick-web-recon.md`)

Fast reconnaissance optimized for speed and essential information gathering.

## Variable Templating

Use `{{vars.variableName}}` to substitute variables:

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
