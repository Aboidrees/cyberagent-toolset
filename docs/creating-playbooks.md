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

## Adding a custom executor (extension)

Executors live in **extensions** — domain modules the engine discovers
automatically. To add one, create a new extension (or add an executor to an
existing domain). See [Architecture](architecture.md) for the full contract.

**1. Create the implementation** `extensions/mytool/src/run.js`:

```javascript
import { validateTarget } from '#sdk';   // shared services (also injected as ctx)
import { execFile } from 'child_process';
import { promisify } from 'util';
const pexecFile = promisify(execFile);

export async function myAction(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const { stdout } = await pexecFile('mytool', ['--some-flag', cleanTarget], {
    timeout: opts.timeoutMs || 30000,
  });
  return { target: cleanTarget, raw: stdout };
}
```

**2. Declare it in the descriptor** `extensions/mytool/index.js`:

```javascript
import { myAction } from './src/run.js';

export default {
  name: 'mytool',
  version: '1.0.0',
  domain: 'mytool',
  description: 'What this extension does.',
  permissions: { network: [], env: [], bins: ['mytool'] },
  executors: [
    {
      uses: 'mytool.action',          // stable logical id used in playbooks
      phase: 'scanning',              // reconnaissance | scanning | gaining-access
      posture: 'active',              // passive | active
      targetTypes: ['domain', 'ip'],
      summary: 'One-line summary shown in the MCP tool description.',
      run: myAction,
      inputSchema: { target: { type: 'string' }, timeoutMs: { type: 'number' } },
    },
  ],
  // Optional: own your findings extraction.
  // report: { findings: (output) => [{ severity: 'high', message: '...' }] },
};
```

**3. Use it in a playbook** — no registration, no code changes:

```yaml
- name: My Custom Check
  uses: mytool.action
  with:
    timeoutMs: 20000
```

Restart the MCP server (or re-run the CLI) and it auto-registers as
`cats_mytool_action` and appears in `cats_capabilities`.

### Shipping it as an installable plugin

Publish the same descriptor as an npm package named `cyberagent-ext-mytool`
(default-export the descriptor from its `main`). Anyone who `npm install`s it gets
the executor automatically — the loader discovers `cyberagent-ext-*` packages.
Plugins use the injected `ctx` (e.g. `ctx.validateTarget`) instead of `#sdk`.

> Always use `execFile` (not `exec`) and `validateTarget` at the top of every
> executor. See [Security considerations](troubleshooting.md#security-notes).
