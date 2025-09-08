---
id: simple-nmap-test
title: Simple Nmap Test
vars:
  target: "scanme.nmap.org"
steps:
  - name: Basic Port Scan
    uses: nmap.scan
    with:
      flags: "-sT -Pn --top-ports 100"
      timeoutMs: 15000
---

## Simple Nmap Test for {{vars.target}}

Testing basic nmap port scanning functionality.
