---
id: nmap-cheat-sheet
title: Nmap Scan Types Reference
vars:
  target: "scanme.nmap.org"
  timeout: 30000
steps:
  # Host Discovery (No Root Required)
  - name: Ping Scan (Host Discovery)
    uses: nmap.scan
    with:
      flags: "-sn"
      timeoutMs: 10000

  # Port Scanning (No Root Required)
  - name: TCP Connect Scan
    uses: nmap.scan
    with:
      flags: "-sT -p 22,80,443"
      timeoutMs: 15000

  - name: Fast Scan (Top 100 Ports)
    uses: nmap.scan
    with:
      flags: "-F"
      timeoutMs: 20000

  - name: Top Ports Scan
    uses: nmap.scan
    with:
      flags: "-sT --top-ports 1000"
      timeoutMs: "{{vars.timeout}}"

  # Service Detection (No Root Required)
  - name: Service Version Detection
    uses: nmap.scan
    with:
      flags: "-sV -p 22,80,443"
      timeoutMs: "{{vars.timeout}}"

  - name: Aggressive Service Detection
    uses: nmap.scan
    with:
      flags: "-sV -sC -p 22,80,443"
      timeoutMs: "{{vars.timeout}}"

  # OS Detection (Limited without Root)
  - name: OS Detection (Best Effort)
    uses: nmap.scan
    with:
      flags: "-O --osscan-guess -p 22,80,443"
      timeoutMs: "{{vars.timeout}}"

  # Script Scanning (No Root Required)
  - name: Default Scripts
    uses: nmap.scan
    with:
      flags: "-sC -p 80,443"
      timeoutMs: "{{vars.timeout}}"

  - name: HTTP Scripts
    uses: nmap.scan
    with:
      flags: "--script http-* -p 80,443"
      timeoutMs: "{{vars.timeout}}"

  # Timing and Performance
  - name: Aggressive Timing
    uses: nmap.scan
    with:
      flags: "-sT -T4 -p 22,80,443"
      timeoutMs: 20000

  - name: Stealth Timing
    uses: nmap.scan
    with:
      flags: "-sT -T2 -p 22,80,443"
      timeoutMs: 45000
---

## Nmap Scan Types Reference for {{vars.target}}

This playbook demonstrates various nmap scan types that work without root privileges.

### Scan Types Included

#### Host Discovery

- **Ping Scan (-sn)**: Discovers live hosts without port scanning

#### Port Scanning  

- **TCP Connect (-sT)**: Full TCP connection (no root required)
- **Fast Scan (-F)**: Scans top 100 most common ports
- **Top Ports (--top-ports N)**: Scans N most common ports

#### Service Detection

- **Version Detection (-sV)**: Determines service versions
- **Script Scanning (-sC)**: Runs default NSE scripts
- **Aggressive (-sV -sC)**: Combines version and script scanning

#### OS Detection

- **OS Detection (-O)**: Attempts OS fingerprinting (limited without root)

#### Specialized Scripts

- **HTTP Scripts (--script http-*)**: Web application scanning
- **Default Scripts (-sC)**: Safe default script collection

#### Timing Options

- **Aggressive (-T4)**: Fast scanning
- **Stealth (-T2)**: Slower, more stealthy scanning

### Root vs Non-Root Scanning

#### ❌ Requires Root (Avoid These)

- `-sS` (SYN scan)
- `-sU` (UDP scan)
- `-sF` (FIN scan)
- `-sX` (Xmas scan)
- `-sN` (Null scan)

#### ✅ No Root Required (Use These)

- `-sT` (TCP connect)
- `-sV` (Version detection)
- `-sC` (Script scanning)
- `-sn` (Ping scan)
- `-F` (Fast scan)
- `--top-ports N`

### Performance Tips

- Use `-T4` for faster scanning on reliable networks
- Use `--top-ports 1000` instead of full port range
- Combine `-sT -Pn` to skip ping and use TCP connect
- Use specific port ranges `-p 80,443,8080` for web apps

### Usage

```bash
node ./src/index.js -p ./playbooks/nmap-cheat-sheet.md --var target=yourtarget.com
```
