# MCP Recon Runner (Node.js)

A powerful, modular reconnaissance orchestrator that automates security reconnaissance workflows through **Markdown-based playbooks**. Execute complex recon tasks (DNS, WHOIS, Nmap, HTTP, TLS, subdomain discovery) and generate both structured JSON and human-readable Markdown reports.

> **⚠️ IMPORTANT: Only test assets you own or have explicit written permission to test. Unauthorized scanning may violate laws and policies.**

## 🎯 Key Features

- **📝 Playbook-Driven**: Define recon workflows in simple Markdown with YAML front-matter
- **🧩 Modular Architecture**: Separate *what to do* (playbooks) from *how to do it* (executors)
- **📊 Dual Output Formats**: Structured JSON for automation + readable Markdown for analysis
- **🔧 Variable Templating**: Dynamic target/parameter substitution with `{{vars.target}}`
- **⚡ Performance Optimized**: Configurable timeouts and non-privileged scan modes
- **🛡️ Security Focused**: Built-in security checks and vulnerability discovery capabilities
- **☁️ Cloud-Native Ready**: API and microservices discovery for modern applications

---

## 📋 Prerequisites

- **Node.js 18+**
- **nmap** (for port scanning) - Install via:

  ```bash
  # macOS
  brew install nmap
  
  # Ubuntu/Debian
  sudo apt install nmap
  
  # CentOS/RHEL
  sudo yum install nmap
  ```

- **Network tools** (usually pre-installed):
  - **ping** - Basic connectivity testing
  - **traceroute** (Unix/macOS) or **tracert** (Windows) - Network path analysis

  ```bash
  # Install traceroute if missing (usually pre-installed)
  # Ubuntu/Debian
  sudo apt install traceroute
  
  # CentOS/RHEL  
  sudo yum install traceroute
  ```

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/yourusername/mcp-recon-runner.git
cd mcp-recon-runner
npm install
```

### Basic Usage

```bash
# Quick reconnaissance with default playbook
npm run recon

# Target-specific reconnaissance
node ./src/index.js -p ./playbooks/web-basic-recon.md --var target=example.com

# Comprehensive security assessment
node ./src/index.js -p ./playbooks/comprehensive-web-recon.md --var target=example.com

# Fast reconnaissance (optimized for speed)
node ./src/index.js -p ./playbooks/quick-web-recon.md --var target=example.com
```

### Convenience Scripts

```bash
# Reconnaissance playbooks
npm run recon:basic           # Basic web reconnaissance
npm run recon:comprehensive   # Full 37-step analysis
npm run recon:security       # Security-focused assessment
npm run recon:api            # API and cloud service discovery
npm run recon:quick          # Fast 8-step essential checks

# Testing and diagnostics
npm run test:nmap            # Nmap reference and testing
npm run test:network         # Network connectivity diagnostics

# Add custom target to any script
npm run recon:basic -- --var target=example.com
npm run test:network -- --var target=cloudflare.com
```

### Output

Results are automatically saved in `./runs/` as:

- **JSON**: Structured data for automation/integration
- **Markdown**: Human-readable reports with expandable sections

---

## 📚 Available Playbooks

### 🔵 Basic Reconnaissance (`web-basic-recon.md`)

Standard web application reconnaissance covering essential checks:

- DNS resolution (A, AAAA, CNAME, NS, MX, TXT)
- WHOIS domain information
- Port scanning (top 1000 ports)
- HTTP headers analysis
- TLS certificate inspection
- Basic file discovery (robots.txt, sitemap.xml)
- Passive subdomain enumeration

```bash
node ./src/index.js -p ./playbooks/web-basic-recon.md --var target=example.com
```

### 🔴 Comprehensive Reconnaissance (`comprehensive-web-recon.md`)

Extensive 37-step reconnaissance covering:

- **Complete DNS Intelligence**: All record types + reverse DNS
- **Multi-Port Scanning**: Top ports + common web ports + service detection  
- **Web Application Discovery**: Admin panels, APIs, config files, dev artifacts
- **Technology Fingerprinting**: CMS detection, server identification
- **Security Analysis**: Headers evaluation, error page analysis
- **Cloud/CDN Detection**: Platform and service identification

```bash
node ./src/index.js -p ./playbooks/comprehensive-web-recon.md --var target=example.com
```

### 🟠 Security-Focused Assessment (`web-security-recon.md`)

Vulnerability-oriented reconnaissance targeting:

- **Information Disclosure**: Exposed config files (.env, .git, backups)
- **Administrative Interfaces**: Admin panels, database tools, control panels
- **API Security**: Documentation exposure, GraphQL introspection
- **Technology Vulnerabilities**: Framework-specific issues (WordPress, Laravel, Django)
- **Server Information Leakage**: Status pages, logs, debug information

```bash
node ./src/index.js -p ./playbooks/web-security-recon.md --var target=example.com
```

### 🟡 API & Cloud Service Discovery (`api-cloud-recon.md`)

Modern application reconnaissance for:

- **API Discovery**: REST endpoints, GraphQL, Swagger documentation
- **Cloud Platform Detection**: AWS, Azure, GCP services
- **Microservices Architecture**: Health checks, service discovery, metrics
- **Authentication Systems**: OAuth, SAML, JWT configuration
- **Serverless Platforms**: Lambda, Netlify, Vercel functions
- **CDN & Edge Services**: Akamai, CloudFlare, Fastly detection

```bash
node ./src/index.js -p ./playbooks/api-cloud-recon.md --var target=api.example.com
```

### 🟢 Quick Reconnaissance (`quick-web-recon.md`)

Fast 8-step essential reconnaissance optimized for speed:

- Basic DNS resolution (A/AAAA records)
- HTTP/HTTPS headers analysis
- Essential files (robots.txt, sitemap.xml)
- TLS certificate information
- Passive subdomain discovery

```bash
node ./src/index.js -p ./playbooks/quick-web-recon.md --var target=example.com
```

### 🟣 Nmap Reference (`nmap-cheat-sheet.md`)

Comprehensive nmap testing and reference covering:

- Host discovery techniques
- Non-privileged port scanning methods
- Service version detection
- Script-based vulnerability scanning
- Performance optimization strategies

```bash
node ./src/index.js -p ./playbooks/nmap-cheat-sheet.md --var target=scanme.nmap.org
```

### 🔵 Network Connectivity Test (`network-connectivity-test.md`)

Network diagnostics and connectivity analysis:

- **Ping Test**: Basic connectivity and response time measurements
- **Traceroute Analysis**: Network path tracing with optimized performance
- **Cross-Platform Support**: Windows (ping/tracert) and Unix (ping/traceroute)
- **Speed Optimized**: Uses `-n` flag to skip DNS resolution for faster execution

```bash
# Test network connectivity to a target
npm run test:network -- --var target=example.com

# Or run directly
node ./src/index.js -p ./playbooks/network-connectivity-test.md --var target=cloudflare.com
```

---

## 🛠️ Available Executors

### 🌐 DNS Resolution (`dns.resolve`)

Resolves various DNS record types for target domains.

**Supported Record Types**: A, AAAA, CNAME, NS, MX, TXT, PTR, SOA

```yaml
- name: Complete DNS Analysis
  uses: dns.resolve
  with:
    types: ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]
    timeoutMs: 5000
```

### 📋 WHOIS Lookup (`whois.lookup`)

Retrieves domain registration information including registrar, creation date, and contact details.

```yaml
- name: Domain Registration Info
  uses: whois.lookup
  with:
    timeoutMs: 10000
```

### 🔍 Port Scanning (`nmap.scan`)

Performs network port scanning using nmap with flexible configuration.

**Important**: Uses non-privileged scan types by default (`-sT` instead of `-sS`)

```yaml
- name: Web Ports Scan
  uses: nmap.scan
  with:
    flags: "-sT -T4 -p 80,443,8080,8443"
    timeoutMs: 20000
```

**Common Scan Types**:

- `-sT`: TCP connect scan (no root required)
- `-sV`: Service version detection
- `-sC`: Default script scanning
- `-F`: Fast scan (top 100 ports)
- `--top-ports N`: Scan N most common ports

### 🌍 HTTP Analysis (`http.headers`, `http.get`)

Analyzes HTTP responses, headers, and retrieves web content.

```yaml
# Headers analysis
- name: Security Headers Check
  uses: http.headers
  with:
    path: "/"
    scheme: "https"
    headers:
      User-Agent: "ReconBot/1.0"
    timeoutMs: 10000

# Content retrieval
- name: Robots.txt Analysis
  uses: http.get
  with:
    path: "/robots.txt"
    scheme: "https"
    timeoutMs: 8000
```

### 🔐 TLS Certificate Analysis (`tls.inspect`)

Extracts and analyzes TLS/SSL certificate information and cipher suites.

```yaml
- name: HTTPS Certificate Analysis
  uses: tls.inspect
  with:
    port: 443
    timeoutMs: 10000
```

### 🌊 Subdomain Discovery (`subdomains.passive`)

Performs passive subdomain enumeration using certificate transparency logs.

```yaml
- name: Passive Subdomain Discovery
  uses: subdomains.passive
  with:
    sources: ["crtsh"]
    timeoutMs: 15000
```

### 🏓 Network Connectivity (`network.ping`)

Tests basic network connectivity and measures response times using ping.

```yaml
- name: Network Connectivity Test
  uses: network.ping
  with:
    count: 4
    timeoutMs: 10000
```

**Options**:

- `count`: Number of ping packets to send (default: 4)
- `timeoutMs`: Maximum time to wait for completion

### 🗺️ Network Path Tracing (`network.traceroute`)

Traces the network path to the target showing each hop along the route.

```yaml
- name: Network Path Analysis
  uses: network.traceroute
  with:
    maxHops: 10
    timeoutMs: 30000
```

**Options**:

- `maxHops`: Maximum number of hops to trace (default: 30, recommended: 10)
- `timeoutMs`: Maximum time to wait for completion

**Performance Tips**:

- Uses `-n` flag to skip DNS resolution for faster execution
- Reduced hop count (10 instead of 30) speeds up completion
- Most targets are reachable within 10 hops

---

## 📖 Playbook Format

Playbooks are Markdown files with YAML front-matter defining variables and execution steps:

```yaml
---
id: my-custom-recon
title: Custom Reconnaissance Playbook
vars:
  target: "example.com"
  scheme: "https"
  timeout: 15000
steps:
  - name: DNS Resolution
    uses: dns.resolve
    with:
      types: ["A", "AAAA", "CNAME"]
      timeoutMs: "{{vars.timeout}}"
  
  - name: Port Scan
    uses: nmap.scan
    with:
      flags: "-sT --top-ports 1000"
      timeoutMs: 30000
      
  - name: HTTP Headers
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
---

# Custom Recon for {{vars.target}}

This playbook performs custom reconnaissance steps...
```

### 🔧 Variable Templating

Use `{{vars.variableName}}` for dynamic substitution:

- `{{vars.target}}` - Target hostname/IP
- `{{vars.scheme}}` - HTTP scheme (http/https)
- `{{vars.timeout}}` - Timeout values
- `{{vars.topPorts}}` - Number of ports to scan

Variables can be overridden via CLI:

```bash
node ./src/index.js -p ./playbooks/my-playbook.md \
  --var target=example.com \
  --var scheme=https \
  --var timeout=20000
```

---

## 📊 Output Formats

### JSON Output (Structured)

Perfect for automation, dashboards, and integration:

```json
{
  "playbook": {
    "id": "web-basic-recon",
    "title": "Basic Web Recon",
    "path": "./playbooks/web-basic-recon.md"
  },
  "vars": {
    "target": "example.com",
    "scheme": "https"
  },
  "startedAt": "2025-09-07T17:30:00.000Z",
  "endedAt": "2025-09-07T17:32:45.000Z",
  "outputs": [
    {
      "name": "DNS Resolution",
      "uses": "dns.resolve",
      "ok": true,
      "data": {
        "A": ["93.184.216.34"],
        "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]
      }
    }
  ]
}
```

### Markdown Output (Human-Readable)

Expandable sections for easy analysis:

````markdown
# Basic Web Recon
- Target: **example.com**
- Started: 2025-09-07T17:30:00.000Z
- Ended: 2025-09-07T17:32:45.000Z

## Steps & Results

### DNS Resolution `(dns.resolve)`
<details><summary>Success</summary>

```json
{
  "A": ["93.184.216.34"],
  "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]
}
```
</details>
````

---

## ⚡ Performance & Configuration

### Timeout Management

- **Global timeout**: `--timeout 15000` (applies to all steps)
- **Step-specific timeout**: `timeoutMs: 10000` (overrides global)
- **Default timeouts**: 5 minutes for port scans, 10 seconds for HTTP

### Optimized Scanning

```bash
# Fast reconnaissance (5-10 second timeouts)
node ./src/index.js -p ./playbooks/quick-web-recon.md --var target=example.com

# Comprehensive but time-limited
node ./src/index.js -p ./playbooks/comprehensive-web-recon.md --timeout 20000

# Specific timeout per step
node ./src/index.js -p ./playbooks/web-basic-recon.md --var timeout=8000
```

### Non-Privileged Operation

All scans work without root privileges:

- Uses `-sT` (TCP connect) instead of `-sS` (SYN scan)
- Automatic fallback for privilege-required operations
- Clear error messages with suggested alternatives

---

## 🔧 Advanced Usage

### Custom Variables

```bash
# Multiple variable overrides
node ./src/index.js -p ./playbooks/comprehensive-web-recon.md \
  --var target=api.example.com \
  --var scheme=https \
  --var topPorts=2000 \
  --var timeout=25000
```

### Output Directory Management

```bash
# Custom output directory
node ./src/index.js -p ./playbooks/web-basic-recon.md \
  --out ./custom-results \
  --var target=example.com
```

### Batch Processing

```bash
# Process multiple targets
for target in api.example.com admin.example.com portal.example.com; do
  node ./src/index.js -p ./playbooks/comprehensive-web-recon.md --var target=$target
done
```

---

## 🛡️ Security Considerations

### Ethical Usage

- ✅ **Only scan assets you own or have written permission to test**
- ✅ **Respect rate limits and avoid aggressive scanning**
- ✅ **Follow responsible disclosure practices**
- ❌ **Do not scan without explicit authorization**
- ❌ **Do not use for malicious purposes**

### Legal Compliance

- Ensure compliance with local laws and regulations
- Obtain proper authorization before testing
- Document permission and scope of testing
- Follow organizational security policies

### Operational Security

- Use VPN or authorized scanning infrastructure
- Monitor scan intensity to avoid service disruption
- Be aware that scans may trigger security alerts
- Log and audit all reconnaissance activities

---

## 🔌 Extending the Framework

### Creating Custom Executors

1. **Create executor file** (`src/executors/mytool.js`):

    ```javascript
    import { exec } from 'child_process';
    import { promisify } from 'util';

    const pexec = promisify(exec);

    export async function myAction(target, opts = {}) {
    const cmd = `mytool ${opts.flags || ''} ${target}`;
    const { stdout } = await pexec(cmd, { timeout: opts.timeoutMs || 30000 });
    return { command: cmd, raw: stdout };
    }
    ```

2. **Register in runner** (`src/runner.js`):

    ```javascript
    import * as myToolExec from './executors/mytool.js';

    const registry = {
    // ... existing executors
    'mytool.action': myToolExec.myAction
    };
    ```

3. **Use in playbooks**:

    ```yaml
    - name: Custom Tool Scan
    uses: mytool.action
    with:
        flags: "--custom-option"
        timeoutMs: 20000
    ```

### Custom Playbook Development

See `playbooks/_templates.md` for comprehensive examples and patterns:

- Progressive timeout strategies
- Conditional scheme detection
- Multi-port analysis patterns
- Error handling approaches

---

## 🔍 Troubleshooting

### Common Issues

**Nmap Permission Errors**:

```bash
Error: You requested a scan type which requires root privileges
```

**Solution**: Use `-sT` instead of `-sS` in scan flags

**Timeout Errors**:

```bash
Error: operation timed out after 10000ms
```

**Solution**: Increase timeout with `--timeout 30000` or step-specific `timeoutMs`

**DNS Resolution Failures**:

```bash
Error: getaddrinfo ENOTFOUND
```

**Solution**: Verify target hostname and network connectivity

**HTTP Connection Errors**:

```bash
Error: connect ECONNREFUSED
```

**Solution**: Check target availability and firewall settings

```bash
# Check if the target is reachable
ping -c 4 <target>

# Test HTTP connectivity
curl -I <target>
```

### Debug Mode

Enable debug logging by checking executor output in generated reports.

### Performance Optimization

- Use `--top-ports 100` for faster scans
- Set appropriate timeouts based on network conditions
- Use `-T4` timing for faster nmap scans on reliable networks
- Consider parallel execution for multiple targets

---

## 📁 Project Structure

```bash
mcp-recon-runner/
├── src/
│   ├── index.js                 # CLI entrypoint
│   ├── runner.js                # Orchestration engine
│   ├── types.js                 # Type definitions
│   ├── executors/               # Tool wrappers
│   │   ├── dns.js              # DNS resolution
│   │   ├── whois.js            # WHOIS lookup
│   │   ├── nmap.js             # Port scanning
│   │   ├── http.js             # HTTP analysis
│   │   ├── tls.js              # TLS inspection
│   │   └── subdomains.js       # Subdomain discovery
│   └── utils/
│       ├── fsx.js              # File system helpers
│       └── logger.js           # Logging utilities
├── playbooks/                   # Reconnaissance playbooks
│   ├── _templates.md           # Playbook templates/examples
│   ├── web-basic-recon.md      # Standard web recon
│   ├── comprehensive-web-recon.md  # Extensive recon (37 steps)
│   ├── web-security-recon.md   # Security-focused assessment
│   ├── api-cloud-recon.md      # API & cloud discovery
│   ├── quick-web-recon.md      # Fast essential recon
│   └── nmap-cheat-sheet.md     # Nmap reference & testing
├── runs/                        # Auto-generated output directory
│   ├── *.json                  # Structured reports
│   └── *.md                    # Human-readable reports
├── package.json
└── README.md
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add your executor/playbook following existing patterns
4. Test with various targets and configurations
5. Update documentation and examples
6. Submit a pull request

### Development Guidelines

- Follow existing code patterns and naming conventions
- Add comprehensive error handling and timeouts
- Include debug logging for troubleshooting
- Test with both privileged and non-privileged modes
- Document new executors and playbook examples

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## ⚠️ Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The authors are not responsible for any misuse or damage caused by this tool.

**Use responsibly. Test ethically. Stay legal.** 🛡️
