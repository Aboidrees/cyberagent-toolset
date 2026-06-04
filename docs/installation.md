# Installation

## Prerequisites

### Node.js 18 or later

```bash
# Check your version
node --version   # must be >= 18.0.0

# Install via nvm (recommended)
nvm install 18
nvm use 18
```

Download: <https://nodejs.org>

---

### nmap (required for port scanning)

| Platform | Command |
| ---------- | --------- |
| macOS | `brew install nmap` |
| Ubuntu / Debian | `sudo apt install nmap` |
| CentOS / RHEL | `sudo yum install nmap` |
| Windows | Download installer from <https://nmap.org/download> |

Verify: `nmap --version`

---

### traceroute (required for network path tracing)

Usually pre-installed on macOS and most Linux distributions.

```bash
# Ubuntu / Debian (if missing)
sudo apt install traceroute

# CentOS / RHEL
sudo yum install traceroute

# macOS — built in (traceroute)
# Windows — built in (tracert)
```

Verify: `traceroute --version` (Unix) or `tracert` (Windows)

---

### ping

Pre-installed on all platforms. No action needed.

---

## Install CyberAgentToolSet (CATS)

### Option A — from npm (recommended)

```bash
# Global install — exposes the `cyberagent` and `cyberagent-mcp` commands
npm install -g cyberagent-toolset

# Verify
cyberagent --help
```

Or run it without installing:

```bash
npx cyberagent-toolset --help
```

### Option B — from source (for development)

```bash
# Clone
git clone https://github.com/Aboidrees/cyberagent-toolset.git
cd cyberagent-toolset

# Install Node dependencies
npm install
```

That's it. No build step required — the project runs directly as ES modules.

---

## Verify the installation

```bash
# Check the CLI works (use `cyberagent` if installed from npm, or `node src/index.js` from source)
cyberagent --help

# Check the MCP server starts
cyberagent-mcp   # (from source: npm run mcp)
# Expected output:
# Loaded 26 extensions (64 executors), 13 playbooks
# CyberAgentToolSet (CATS) v0.22.0 ready — 86 tools, 4 prompts, resources on
```

Press `Ctrl+C` to stop the MCP server.

---

## Platform notes

### macOS

Everything works out of the box with Homebrew. If nmap requires elevated privileges for certain scan types, use `-sT` (TCP connect scan) which is the default.

### Linux

Some distributions require `sudo` for raw socket operations (nmap SYN scans). The tool defaults to `-sT` which does not require root.

### Windows

- Use `tracert` instead of `traceroute` — the tool detects this automatically.
- PowerShell or WSL both work. Node.js must be in PATH.
- nmap Windows installer: <https://nmap.org/download#windows>

---

## Updating

```bash
git pull
npm install
```
