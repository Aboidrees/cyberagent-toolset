---
id: nmap-test
title: Nmap Testing Playbook
vars:
  target: "8.8.8.8"
  timeout: 30000
steps:
  - name: Basic Nmap Ping Scan
    uses: nmap.scan
    with:
      flags: "-sn"
      timeoutMs: 10000
  
  - name: Quick Port Scan
    uses: nmap.scan
    with:
      flags: "-F"
      timeoutMs: 20000
  
  - name: Top 100 Ports
    uses: nmap.scan
    with:
      flags: "--top-ports 100"
      timeoutMs: "{{vars.timeout}}"
  
  - name: Service Detection
    uses: nmap.scan
    with:
      flags: "-sV -p 53,80,443"
      timeoutMs: "{{vars.timeout}}"
---

## Nmap Testing for {{vars.target}}

This playbook tests various nmap scanning capabilities:

### Test Cases

- Basic ping scan (-sn)
- Fast port scan (-F)
- Top 100 ports scan
- Service version detection (-sV)

### Usage

```bash
node ./src/index.js -p ./playbooks/nmap-test.md --var target=8.8.8.8
```
