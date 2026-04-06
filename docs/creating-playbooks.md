# Creating Playbooks

Playbooks let you define recon workflows without touching any JavaScript. Once created, they appear automatically as MCP tools and CLI targets.

---

## Step 1 — Create the file

Create a `.md` file in the `playbooks/` directory:

```bash
touch playbooks/my-recon.md
```

---

## Step 2 — Write the YAML front matter

The front matter (between `---` markers) defines everything the runner needs:

```yaml
---
id: my-recon                 # required · used as MCP tool name: recon_play__my_recon
title: My Recon Playbook     # required · shown in reports and MCP tool list
vars:
  target: "example.com"      # default target (overridden at runtime)
  scheme: "https"
  timeout: 10000
steps:
  - name: DNS Records
    uses: dns.resolve
    with:
      types: ["A", "AAAA", "NS", "MX", "TXT"]
      timeoutMs: 5000

  - name: HTTP Headers
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
---
```

---

## Step 3 — Add a description (optional)

Text below the closing `---` appears as the playbook description in MCP tool listings and reports:

```markdown
---
(YAML here)
---

## My Recon for {{vars.target}}

Brief description of what this playbook checks and when to use it.
```

---

## Step 4 — Test it

```bash
node src/index.js -p playbooks/my-recon.md --target example.com
```

For MCP, restart Claude Desktop and the playbook will appear in `recon_topics`.

---

## Available executors

| `uses` key | What it does |
| ----------- | -------------- |
| `dns.resolve` | DNS records (A, AAAA, NS, MX, TXT, CNAME, PTR, SOA) |
| `whois.lookup` | WHOIS registration data |
| `nmap.scan` | Port scanning |
| `http.headers` | HTTP response headers |
| `http.get` | HTTP GET with body snippet |
| `tls.inspect` | TLS certificate + cipher |
| `subdomains.passive` | Passive subdomain enumeration |
| `network.ping` | ICMP ping |
| `network.traceroute` | Traceroute hop-by-hop |

Full options for each: [executors.md](executors.md)

---

## Variable templating

Use `{{vars.name}}` to reference playbook variables inside `with:` values:

```yaml
vars:
  target: "example.com"
  timeout: 10000
  scheme: "https"

steps:
  - name: Homepage
    uses: http.get
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
```

Templates that resolve to a pure number are automatically cast to `number` type (important for `timeoutMs`).

---

## Patterns and recipes

### Probe multiple paths

```yaml
steps:
  - name: robots.txt
    uses: http.get
    with:
      path: "/robots.txt"
      scheme: "{{vars.scheme}}"

  - name: sitemap.xml
    uses: http.get
    with:
      path: "/sitemap.xml"
      scheme: "{{vars.scheme}}"

  - name: security.txt
    uses: http.get
    with:
      path: "/.well-known/security.txt"
      scheme: "{{vars.scheme}}"
```

### Try both HTTP and HTTPS

```yaml
steps:
  - name: HTTPS Headers
    uses: http.headers
    with:
      path: "/"
      scheme: "https"

  - name: HTTP Headers (fallback)
    uses: http.headers
    with:
      path: "/"
      scheme: "http"
```

### Targeted port scan then service fingerprint

```yaml
vars:
  target: "example.com"
  ports: "80,443,8080,8443,3000,5000"

steps:
  - name: Web Port Scan
    uses: nmap.scan
    with:
      flags: "-sT -Pn -p {{vars.ports}}"
      timeoutMs: 60000

  - name: Service Detection
    uses: nmap.scan
    with:
      flags: "-sV -Pn -p {{vars.ports}}"
      timeoutMs: 90000
```

### Check for exposed sensitive files

```yaml
steps:
  - name: .env file
    uses: http.get
    with:
      path: "/.env"

  - name: .git directory
    uses: http.get
    with:
      path: "/.git/HEAD"

  - name: Docker compose
    uses: http.get
    with:
      path: "/docker-compose.yml"

  - name: backup archive
    uses: http.get
    with:
      path: "/backup.zip"
```

---

## Adding a custom executor

If the built-in executors don't cover your use case:

1. Create `src/executors/mytool.js`:

```javascript
import { execFile } from 'child_process';
import { promisify } from 'util';
import { validateTarget } from '../utils/validate.js';

const pexecFile = promisify(execFile);

export async function myAction(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const args = ['--some-flag', cleanTarget];
  const { stdout } = await pexecFile('mytool', args, {
    timeout: opts.timeoutMs || 30000,
  });
  return { target: cleanTarget, raw: stdout };
}
```

1. Register it in `src/runner.js`:

```javascript
import * as myToolExec from './executors/mytool.js';

const registry = {
  // ... existing entries
  'mytool.action': myToolExec.myAction,
};
```

1. Use it in a playbook:

```yaml
- name: My Custom Check
  uses: mytool.action
  with:
    timeoutMs: 20000
```

> Always use `execFile` (not `exec`) and call `validateTarget` at the top of every executor. See [Security considerations](troubleshooting.md#security-notes) for why this matters.
