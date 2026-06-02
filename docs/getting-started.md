# Getting Started

## Your first recon in 5 minutes

### 1. Pick a target

Always use a domain you own or have written permission to test.
For learning, `scanme.nmap.org` is a public host maintained by nmap specifically for this purpose.

### 2. Run a quick recon

```bash
node src/index.js -p playbooks/quick-web-recon.yaml --target scanme.nmap.org
```

You will see step-by-step progress in the terminal. When it finishes:

```TEXT
✅ Done.
JSON:     runs/Quick_Web_Reconnaissance_2026-04-06T11-30-00-000Z.json
Markdown: runs/Quick_Web_Reconnaissance_2026-04-06T11-30-00-000Z.md
```

### 3. Open the Markdown report

The `.md` report has collapsible sections for every step — open it in any Markdown viewer (VS Code, Obsidian, GitHub, etc.).

### 4. Try a deeper scan

```bash
# Full infrastructure + web + security sweep
node src/index.js -p playbooks/web-basic-recon.yaml --target scanme.nmap.org
```

---

## Understanding the output

Every run produces two files in `runs/`:

### JSON report (`.json`)

Machine-readable. Useful for scripting, dashboards, and feeding findings into other tools.

```json
{
  "playbook": { "id": "quick-web-recon", "title": "Quick Web Reconnaissance" },
  "vars": { "target": "scanme.nmap.org" },
  "startedAt": "2026-04-06T11:30:00.000Z",
  "endedAt":   "2026-04-06T11:31:45.000Z",
  "outputs": [
    {
      "name": "DNS A Records",
      "uses": "dns.resolve",
      "ok": true,
      "data": { "A": ["45.33.32.156"] }
    },
    {
      "name": "TLS Certificate",
      "uses": "tls.inspect",
      "ok": false,
      "error": "TLS connect timeout after 12000ms"
    }
  ]
}
```

Each step entry has:

- `ok: true` — step succeeded, results are in `data`
- `ok: false` — step failed, reason is in `error` (non-fatal, the run continues)

### Markdown report (`.md`)

Human-readable. Each step has a collapsible `<details>` block containing the full JSON result.

---

## npm convenience scripts

```bash
npm run recon:quick          # quick-web-recon (no target — edit playbook or pass --var)
npm run recon:basic          # web-basic-recon
npm run recon:comprehensive  # comprehensive-web-recon (37 steps, ~5 min)
npm run recon:security       # web-security-recon
npm run recon:api            # api-cloud-recon
npm run test:network         # ping + traceroute diagnostics
```

Pass a target to any script:

```bash
npm run recon:basic -- --target example.com
npm run recon:security -- --target example.com
```

---

## Choosing the right playbook

| I want to... | Use |
| --- | --- |
| Get a fast overview in under 2 minutes | `quick-web-recon` |
| Do a thorough baseline assessment | `web-basic-recon` |
| Find exposed files, admin panels, secrets | `web-security-recon` |
| Map the full infrastructure deeply | `comprehensive-web-recon` |
| Assess a REST API or microservices platform | `api-cloud-recon` |
| Check network reachability and routing | `network-connectivity-test` |

See [playbooks.md](playbooks.md) for full descriptions.

---

## Using with Claude (MCP mode)

Start the MCP server once and Claude can run recon interactively:

```bash
npm run mcp
```

Then in Claude, say: **"Run recon on example.com"**

Claude will list the available playbooks, ask which topics you want, run them, and summarise the findings. See [MCP Integration](mcp-integration.md) for full setup.
