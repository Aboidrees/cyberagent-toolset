# MCP Integration

CyberAgentToolSet (CATS) implements the [Model Context Protocol](https://modelcontextprotocol.io) so Claude (or any MCP client) can call recon tools directly from a conversation.

---

## How it works

The MCP server runs as a local subprocess on your machine. Claude Desktop launches it automatically on startup and communicates over stdio using JSON-RPC 2.0. When you ask Claude to run a recon, it calls the appropriate tool, your machine executes it with full network access, and the results come back to Claude.

```TEXT
You ──► Claude Desktop
              │
              │  MCP / stdio JSON-RPC
              ▼
        mcp-server.js   (your machine, full network)
              │
         ┌────┴────────────────────┐
         │   recon executors       │
         │  dns · nmap · http ...  │
         └─────────────────────────┘
```

---

## Setup

### 1. Find the absolute path to the server

```bash
# macOS / Linux
realpath src/mcp-server.js
# e.g.  /Users/yourname/development/cyberagent-toolset/src/mcp-server.js
```

### 2. Add the server to Claude Desktop config

Open (or create) `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "recon": {
      "command": "node",
      "args": [
        "/Users/yourname/development/cyberagent-toolset/src/mcp-server.js"
      ]
    }
  }
}
```

Replace the path with your actual absolute path.

### 3. Restart Claude Desktop

Fully quit (`Cmd+Q` / `Alt+F4`) and reopen. Claude Desktop will start the MCP server as a background subprocess.

### 4. Verify

In Claude, ask: **"List available recon topics"**

Claude will call `cats_topics` and show you the 13 playbooks with descriptions.

---

## Interactive recon flow

Once connected, the typical flow looks like this:

```TEXT
You:    "Run recon on example.com"

Claude: calls cats_topics → gets list of playbooks

Claude: "Which topics do you want to run?
         ☐ Quick Web Recon (8 steps — DNS, headers, TLS, subdomains)
         ☐ Web Security Recon (32 steps — exposed files, admin panels, secrets)
         ☐ Comprehensive Web Recon (37 steps — full infrastructure sweep)
         ☐ API & Cloud Recon (39 steps — REST, GraphQL, cloud services)
         ☐ Web Basic Recon (7 steps — DNS, WHOIS, ports, HTTP, TLS)
         ☐ Network Connectivity Test (2 steps — ping + traceroute)"

You:    "Quick Web Recon and Web Security Recon"

Claude: calls cats_run_multi {
          target: "example.com",
          playbooks: ["quick-web-recon", "web-security-recon"]
        }

Claude: presents findings, highlights issues
```

---

## Available MCP tools

### Discovery

| Tool | Description |
| ------ | ------------- |
| `cats_capabilities` | List every executor grouped by phase / posture / domain |
| `cats_topics` | List all playbooks with full metadata (id, title, steps, executors) |

### Playbook runners

| Tool | Description |
| ------ | ------------- |
| `cats_run` | Run a single playbook: `{ target, playbook, vars? }` |
| `cats_run_multi` | Run multiple playbooks in one call: `{ target, playbooks: [] }` |
| `cats_play__<id>` | Direct shortcut per playbook, e.g. `cats_play__quick_web_recon` |

### Assessment (stateful — the agent-driven loop)

A stateful investigation: each result feeds an entity graph and a pivot engine
that suggests the next best actions. Prefer this over one-off executor calls for
a full assessment.

| Tool | Description |
| ------ | ------------- |
| `cats_assess_start` | Start an assessment: `{ target, passive? }` → `assessmentId` + ranked suggestions |
| `cats_assess_run` | Run the top-N suggestions (or a specific `uses`): folds results in, returns discoveries + new suggestions |
| `cats_assess_next` | List the ranked next-best actions without running them |
| `cats_assess_report` | Synthesize a prioritized report (CVE × EPSS correlation, entity inventory, coverage) |

Typical agent loop: `cats_assess_start` → `cats_assess_run` (repeat as new
entities surface) → `cats_assess_report`.

### Low-level executor tools

Every executor is exposed as `cats_<uses>` (the `uses` key with dots → underscores),
generated from the extension catalog. Examples:

| Tool | `uses` key | Phase · Domain |
| ---- | ---------- | -------------- |
| `cats_dns_resolve` | `dns.resolve` | reconnaissance · dns |
| `cats_whois_lookup` | `whois.lookup` | reconnaissance · whois |
| `cats_email_security` | `email.security` | reconnaissance · email |
| `cats_ip_intel` | `ip.intel` | reconnaissance · ip-intel |
| `cats_nmap_scan` | `nmap.scan` | scanning · network |
| `cats_http_security_score` | `http.security_score` | scanning · web |
| `cats_tls_deep` | `tls.deep` | scanning · tls |
| `cats_vuln_cve_lookup` | `vuln.cve_lookup` | reconnaissance · threat-intel |
| `cats_cloud_bucket_finder` | `cloud.bucket_finder` | gaining-access · cloud |
| … | … | … |

Call **`cats_capabilities`** for the full, live list (it reflects any installed
extensions, including npm `cyberagent-ext-*` plugins).

`cats_execute` runs **any** executor generically: `{ uses, target, opts? }` — the
single entry point used in lean mode.

---

## Resources

The server exposes readable state as MCP resources (the agent can fetch and cite
these without a tool call):

| URI | Contents |
| --- | -------- |
| `cats://capabilities` | Every executor by phase / posture / domain (JSON) |
| `cats://assessments` | Index of saved assessments |
| `cats://assessment/{id}` | A raw assessment session (entities, findings, steps) |
| `cats://assessment/{id}/report` | The synthesized prioritized report (Markdown) |

---

## Prompts

One-click agent workflows (surfaced as slash-style prompts in MCP clients):

| Prompt | Arguments | What it does |
| ------ | --------- | ------------ |
| `assess-domain` | `target`, `passive?` | Drives a full assessment loop (start → run → pivot → report) |
| `triage-findings` | `assessmentId` | Prioritizes an assessment's findings into a remediation plan |
| `passive-osint` | `target` | Passive-only footprint — nothing touches the host |
| `quick-recon` | `target` | Fast essentials — DNS, TLS, headers, subdomains |

---

## Lean tool mode

Many MCP clients pick tools better with a smaller surface. Set
`CATS_TOOL_MODE=lean` to hide the 60 per-executor tools (82 → 22): the agent
discovers executors via `cats_capabilities` and runs any of them via
`cats_execute`, while the assessment verbs (`cats_assess_*`) and playbook tools
stay front-and-center.

```json
{ "mcpServers": { "cyberagent": {
    "command": "node",
    "args": ["/abs/path/to/src/mcp-server.js"],
    "env": { "CATS_TOOL_MODE": "lean" }
} } }
```

---

## Adding a new playbook

1. Drop a `.yaml` file into `playbooks/` following the [playbook format](playbooks.md).
2. Make sure it has an `id`, `title`, and `description`.
3. Restart Claude Desktop.

The new playbook automatically appears as a tool (`cats_play__<id>`) and in the `cats_topics` list — no code changes needed.

---

## Running the server manually (testing)

```bash
npm run mcp
# stderr output:
# Loaded 22 extensions (60 executors), 13 playbooks
# CyberAgentToolSet (CATS) v0.16.0 ready — 82 tools, 4 prompts, resources on

# Send a raw tools/list request
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node src/mcp-server.js 2>/dev/null
```

---

## Troubleshooting the MCP connection

### **Claude doesn't show recon tools after restart**

- Check the path in `claude_desktop_config.json` is absolute and correct.
- Run `node /your/path/src/mcp-server.js` manually and confirm it prints the startup message.
- Check Claude Desktop logs: `~/Library/Logs/Claude/` (macOS).

#### **"Cannot find module" error**

- Run `npm install` inside the project directory.

#### **Tools show but calls return errors**

- The server is connected. The error is from the executor (e.g. nmap not installed, network unreachable). See [Troubleshooting](troubleshooting.md).
