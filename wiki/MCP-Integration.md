# MCP Integration

CATS implements the Model Context Protocol, so Claude (or any MCP client) can call
its tools directly.

## Setup (Claude Desktop)

`~/.claude/claude_desktop_config.json`:
```json
{ "mcpServers": { "cyberagent": {
    "command": "node",
    "args": ["/abs/path/to/cyberagent-toolset/src/mcp-server.js"]
} } }
```
Restart Claude Desktop fully.

## Tools

| Tool | Purpose |
| ---- | ------- |
| `cats_capabilities` | List every executor by phase / posture / domain |
| `cats_topics` | List all playbooks with metadata |
| `cats_run` | Run one playbook: `{ target, playbook }` |
| `cats_run_multi` | Run several: `{ target, playbooks: [] }` |
| `cats_play__<id>` | Shortcut per playbook |
| `cats_<uses>` | One tool per executor (e.g. `cats_http_security_score`) |

## Verify manually

```bash
npm run mcp
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node src/mcp-server.js 2>/dev/null
```

Keys from `.env` are available to the server automatically (see [[API Keys]]).
