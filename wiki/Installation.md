# Installation

## Prerequisites

- **Node.js ≥ 18**
- Optional binaries (only for the network executors): **`nmap`**, **`traceroute`**
  - macOS: `brew install nmap` (traceroute is preinstalled)
  - Debian/Ubuntu: `sudo apt install nmap traceroute`

## Install

```bash
git clone https://github.com/Aboidrees/cyberagent-toolset.git
cd cyberagent-toolset
npm install
```

## Verify

```bash
# CLI
node src/index.js --help

# Run the diagnostic playbook (exercises every executor once)
node src/index.js -p playbooks/all-tools-selftest.yaml --target example.com

# MCP server (Ctrl-C to stop)
npm run mcp
# → CyberAgentToolSet (CATS) v0.12.0 ready — 73 tools
```

## Optional: API keys

Everything runs keyless. To enable extra enrichment, copy `.env.example` to `.env`
and add keys — see [[API Keys]]. The `.env` file is loaded automatically.

## Optional: global command

`npm link` (or `npm install -g .`) exposes the `cyberagent` and `cyberagent-mcp`
bins so you can run `cyberagent -p …` from anywhere.
