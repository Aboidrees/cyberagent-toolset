# MCP Recon Runner (Node.js)

A lightweight, playbook-driven recon orchestrator written in Node.js. Write recon steps in Markdown, the runner executes them (DNS, WHOIS, Nmap, HTTP, TLS, passive subdomains) and outputs JSON + Markdown reports.

> **Only test assets you own or have written permission to test.**

## Prerequisites

- Node.js 18+
- `nmap` installed if you use the `nmap.scan` step (optional but recommended)

## Install

```bash
npm i
```

## Run

```bash
# Basic run (uses playbooks/web-basic-recon.md)
npm run recon

# Override target and scheme via CLI
node ./src/index.js -p ./playbooks/web-basic-recon.md --var target=example.com --var scheme=https
```

Outputs are saved in `./runs` as both JSON and Markdown reports.

## Extending

- Add new executors in `src/executors/yourtool.js`
- Register them in `src/runner.js` under the `registry`
- Create a playbook in `/playbooks` referencing `uses: yourtool.action`

This project demonstrates how to orchestrate reconnaissance tasks in a modular way, suitable for integration with larger systems or LLM agents.