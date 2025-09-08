---
id: web-security-recon
title: Web Application Security Reconnaissance
vars:
  target: "example.com"
  scheme: "https"
  timeout: 10000
  userAgent: "Mozilla/5.0 (compatible; SecurityBot/1.0)"
steps:
  # Basic Security Headers Analysis
  - name: Security Headers Check
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      headers:
        User-Agent: "{{vars.userAgent}}"
      timeoutMs: "{{vars.timeout}}"

  # SSL/TLS Security Analysis
  - name: TLS Configuration Analysis
    uses: tls.inspect
    with:
      port: 443
      timeoutMs: 15000

  # Common Vulnerability Paths
  - name: .well-known/security.txt
    uses: http.get
    with:
      path: "/.well-known/security.txt"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
  
  - name: Exposed .env Files
    uses: http.get
    with:
      path: "/.env"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Exposed .git Directory
    uses: http.get
    with:
      path: "/.git/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Exposed .git/config
    uses: http.get
    with:
      path: "/.git/config"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Exposed Docker Files
    uses: http.get
    with:
      path: "/Dockerfile"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Exposed .dockerignore
    uses: http.get
    with:
      path: "/.dockerignore"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Configuration Files
  - name: Web.config Exposure
    uses: http.get
    with:
      path: "/web.config"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: .htaccess Exposure
    uses: http.get
    with:
      path: "/.htaccess"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: phpinfo() Exposure
    uses: http.get
    with:
      path: "/phpinfo.php"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Backup Files
  - name: Database Backup Files
    uses: http.get
    with:
      path: "/backup.sql"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Site Backup Files
    uses: http.get
    with:
      path: "/backup.zip"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Old Site Backup
    uses: http.get
    with:
      path: "/old/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Admin/Management Interfaces
  - name: Admin Interface
    uses: http.get
    with:
      path: "/admin/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Management Interface
    uses: http.get
    with:
      path: "/manage/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Control Panel
    uses: http.get
    with:
      path: "/cpanel/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: PHPMyAdmin
    uses: http.get
    with:
      path: "/phpmyadmin/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # API Security Check
  - name: API Documentation
    uses: http.get
    with:
      path: "/api/docs"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Swagger UI
    uses: http.get
    with:
      path: "/swagger-ui/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: GraphQL Introspection
    uses: http.get
    with:
      path: "/graphql"
      scheme: "{{vars.scheme}}"
      headers:
        Content-Type: "application/json"
      timeoutMs: "{{vars.timeout}}"

  # Server Information Disclosure
  - name: Server Status
    uses: http.get
    with:
      path: "/server-status"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Server Info
    uses: http.get
    with:
      path: "/server-info"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Technology-Specific Checks
  - name: WordPress wp-config Backup
    uses: http.get
    with:
      path: "/wp-config.php.bak"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: WordPress Debug Log
    uses: http.get
    with:
      path: "/wp-content/debug.log"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Laravel .env
    uses: http.get
    with:
      path: "/.env"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Django Settings
    uses: http.get
    with:
      path: "/settings.py"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Log Files
  - name: Error Logs
    uses: http.get
    with:
      path: "/error.log"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Access Logs
    uses: http.get
    with:
      path: "/access.log"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Development Artifacts
  - name: Source Maps
    uses: http.get
    with:
      path: "/main.js.map"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Package.json
    uses: http.get
    with:
      path: "/package.json"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Composer.json
    uses: http.get
    with:
      path: "/composer.json"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
---

## Web Application Security Reconnaissance for {{vars.target}}

This specialized security-focused playbook identifies potential security vulnerabilities and information disclosure issues including:

### Security Headers Analysis

- HTTP security headers evaluation
- TLS/SSL configuration assessment

### Information Disclosure Detection

- Exposed configuration files (.env, web.config, .htaccess)
- Source code exposure (.git, backup files)
- Development artifacts (source maps, package files)

### Administrative Interface Discovery

- Admin panels and management interfaces
- Database administration tools
- Control panels

### API Security Assessment

- API documentation exposure
- GraphQL introspection
- Swagger/OpenAPI endpoints

### Technology-Specific Vulnerabilities

- WordPress configuration exposure
- Laravel environment files
- Django settings disclosure

### Server Information Leakage

- Server status pages
- Error and access logs
- Debug information

⚠️ **IMPORTANT SECURITY NOTICE**
This playbook is designed for authorized security testing only. Ensure you have explicit permission to test the target system. Unauthorized scanning may violate laws and policies.

### Usage

```bash
node ./src/index.js -p ./playbooks/web-security-recon.md --var target=authorized-target.com
```
