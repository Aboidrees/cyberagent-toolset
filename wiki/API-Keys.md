# API Keys

Everything runs **keyless**. Keys only add enrichment. Copy `.env.example` to
`.env` and fill in what you have — it is **loaded automatically** by the CLI and
the MCP server, for both built-in and npm-installed extensions. Real shell env
vars override `.env`.

```bash
cp .env.example .env
```

## Supported keys

| Variable | Enables | Cost | Where to get it |
| -------- | ------- | ---- | --------------- |
| `SHODAN_API_KEY` | `shodan.host` (no-op without it) | **Paid** (one-time membership) | account.shodan.io |
| `NVD_API_KEY` | raises `vuln.cve_lookup` rate limit | **Free** | nvd.nist.gov/developers/request-an-api-key |
| `ABUSEIPDB_API_KEY` | `ip.intel` abuse-reputation score | **Free tier** (1k/day) | abuseipdb.com/register |
| `SLACK_WEBHOOK_URL` | Slack run notifications | **Free** | api.slack.com/messaging/webhooks |
| `WEBHOOK_URL` | generic JSON webhook | **Free** (self-hosted) | your endpoint |
| `NOTIFY_ON_SEVERITY` | severity gate for notifications (`high,critical` default, or `all`) | — | — |

## Passing a key per step

```yaml
- name: Shodan Host Data
  uses: shodan.host
  with:
    apiKey: "{{env.SHODAN_API_KEY}}"
```

## Notes

- `.env` is gitignored — never commit real keys.
- For the MCP server launched by Claude Desktop, `.env` in the project root is
  still picked up (the path is resolved relative to the install, not the cwd). You
  can also set keys via the `env` block in the MCP server config.
