# User Guide

Scenario-driven tour. Concepts first, then one section per use case.

## Concepts

- **Executor** — one capability, keyed by a stable `uses:` string (e.g.
  `dns.resolve`, `http.security_score`).
- **Extension** — a domain module (dns, web, tls, cloud, …) shipping executors.
  Local `extensions/` load out of the box; npm `cyberagent-ext-*` packages
  auto-register. See [[Extensions]].
- **Playbook** — a YAML workflow (`playbooks/*.yaml`) of executor steps. See
  [[Playbooks]].
- **Phase / posture** — each executor is `reconnaissance | scanning |
  gaining-access` and `passive | active`. List all via the MCP `cats_capabilities`
  tool.

## Scenario: quick recon

```bash
node src/index.js -p playbooks/quick-web-recon.yaml --target example.com
```

## Scenario: targeted assessment

Use a focused playbook — email, TLS, headers, vulnerability, OWASP, or cloud (see
[[Quick Start]] table). Override vars with `--var key=value`.

## Scenario: API keys

Copy `.env.example` → `.env`, add keys; loads automatically. See [[API Keys]].

## Scenario: passive-only (limited authorization)

Run passive playbooks (e.g. `email-security-assessment`) — no packets reach the
target. Check posture with `cats_capabilities`. Active stages carry a ⚠ notice.

## Scenario: drive from Claude (MCP)

Add the server to Claude Desktop, then ask it to list/run topics or call any
`cats_<uses>` executor tool. See [[MCP Integration]].

## Scenario: automation

Diff two runs, batch a watchlist, schedule recurring scans, export reports — see
[[Automation]].

## Scenario: write a playbook

```bash
cp playbooks/_template.yaml playbooks/my-recon.yaml
node src/index.js -p playbooks/my-recon.yaml --target example.com
```

## Scenario: add or install an extension

Local descriptor or `npm install cyberagent-ext-<name>` — see [[Extensions]].

## Safety

Active stages (scanning, web, fuzzing, bucket probing) send traffic. Authorized
targets only. Passive/OSINT and vuln-intel checks never touch the target host.
