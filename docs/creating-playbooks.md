# Creating Playbooks

Playbooks let you define recon workflows without touching any JavaScript. Once created, they appear automatically as MCP tools and CLI targets.

---

## Step 1 — Create the file

Copy the skeleton to a new `.yaml` file in the `playbooks/` directory:

```bash
cp playbooks/_template.yaml playbooks/my-recon.yaml
```

---

## Step 2 — Write the YAML

A playbook is pure YAML with three required keys (`id`, `title`, `description`)
plus optional `vars` and a list of `steps`:

```yaml
id: my-recon                 # required · used as MCP tool name: cats_play__my_recon
title: My Recon Playbook     # required · shown in reports and MCP tool list
description: One-line summary shown in the MCP tool listing and reports.
vars:
  target: example.com        # default target (overridden at runtime)
  scheme: https
  timeout: 10000
steps:
  - name: DNS Records
    uses: dns.resolve
    with:
      types: [A, AAAA, NS, MX, TXT]
      timeoutMs: 5000

  - name: HTTP Headers
    uses: http.headers
    parallel: true            # optional · runs concurrently with adjacent parallel steps
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
```

The `description:` field is what appears in MCP tool listings and reports. Files
whose name starts with `_` (like `_template.yaml`) are skipped by the loader.

> Legacy `.md` playbooks (YAML front matter between `---` markers, description as
> the first body paragraph) are still loaded for backward compatibility, but new
> playbooks should be `.yaml`.

---

## Step 3 — Test it

```bash
node src/index.js -p playbooks/my-recon.yaml --target example.com
```

For MCP, restart Claude Desktop and the playbook will appear in `cats_topics`.

---

## Available executors

| Stage | `uses` keys |
| ----- | ----------- |
| **PASSIVE / OSINT** | `dns.resolve` · `dns.reverse` · `whois.lookup` · `subdomains.passive` · `email.security` · `ip.intel` |
| **LIVENESS** | `network.ping` · `network.traceroute` |
| **PORTSCAN** | `nmap.scan` |
| **WEBSCANNER** | `http.headers` · `http.get` · `http.security_score` · `http.waf_detect` · `http.fingerprint` · `http.cors_check` · `http.methods` · `tls.inspect` · `tls.deep` |
| **VULN INTELLIGENCE** | `vuln.cve_lookup` · `shodan.host` (key-gated) |
| **ESCALATION** | `cloud.bucket_finder` · `http.fuzz_paths` · `http.git_leak` |

Full options and return shapes for each: [executors.md](executors.md)

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
