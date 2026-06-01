# MCP Integration

MCP Recon Runner implements the [Model Context Protocol](https://modelcontextprotocol.io) so Claude (or any MCP client) can call recon tools directly from a conversation.

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
# e.g.  /Users/yourname/development/mcp-recon-runner/src/mcp-server.js
```

### 2. Add the server to Claude Desktop config

Open (or create) `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "recon": {
      "command": "node",
      "args": [
        "/Users/yourname/development/mcp-recon-runner/src/mcp-server.js"
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

Claude will call `recon_topics` and show you the 7 playbooks with descriptions.

---

## Interactive recon flow

Once connected, the typical flow looks like this:

```TEXT
You:    "Run recon on cyberany.org"

Claude: calls recon_topics → gets list of playbooks

Claude: "Which topics do you want to run?
         ☐ Quick Web Recon (8 steps — DNS, headers, TLS, subdomains)
         ☐ Web Security Recon (32 steps — exposed files, admin panels, secrets)
         ☐ Comprehensive Web Recon (37 steps — full infrastructure sweep)
         ☐ API & Cloud Recon (39 steps — REST, GraphQL, cloud services)
         ☐ Web Basic Recon (7 steps — DNS, WHOIS, ports, HTTP, TLS)
         ☐ Network Connectivity Test (2 steps — ping + traceroute)"

You:    "Quick Web Recon and Web Security Recon"

Claude: calls recon_run_multi {
          target: "cyberany.org",
          playbooks: ["quick-web-recon", "web-security-recon"]
        }

Claude: presents findings, highlights issues
```

---

## Available MCP tools

### Discovery

| Tool | Description |
| ------ | ------------- |
| `recon_topics` | List all playbooks with full metadata (id, title, steps, executors) |

### Playbook runners

| Tool | Description |
| ------ | ------------- |
| `recon_run` | Run a single playbook: `{ target, playbook, vars? }` |
| `recon_run_multi` | Run multiple playbooks in one call: `{ target, playbooks: [] }` |
| `recon_play__<id>` | Direct shortcut per playbook, e.g. `recon_play__quick_web_recon` |

### Low-level executor tools

| Tool | What it calls |
| ------ | -------------- |
| `recon_dns` | DNS resolution (any record types) |
| `recon_whois` | WHOIS lookup |
| `recon_nmap` | nmap port scan |
| `recon_http_headers` | HTTP response headers |
| `recon_http_get` | HTTP GET with body snippet |
| `recon_tls` | TLS certificate + cipher inspection |
| `recon_subdomains` | Passive subdomain enumeration (crt.sh) |
| `recon_ping` | ICMP ping with statistics |
| `recon_traceroute` | Traceroute with hop-by-hop detail |

---

## Adding a new playbook

1. Drop a `.md` file into `playbooks/` following the [playbook format](playbooks.md).
2. Make sure it has an `id` and `title` in the YAML front matter.
3. Restart Claude Desktop.

The new playbook automatically appears as a tool (`recon_play__<id>`) and in the `recon_topics` list — no code changes needed.

---

## Running the server manually (testing)

```bash
npm run mcp
# stderr output:
# Loaded 7 playbooks: all-tools-selftest, api-cloud-recon, web-basic-recon, ...
# MCP Recon Runner v0.3.0 ready — 19 tools registered

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
