---
id: network-connectivity-test
title: Network Connectivity Test
vars:
  target: "google.com"
steps:
  - name: Ping Test
    uses: network.ping
    with:
      count: 4
      timeoutMs: 10000

  - name: Traceroute
    uses: network.traceroute
    with:
      maxHops: 20
      timeoutMs: 45000
---

## Network Connectivity Test for {{vars.target}}

Tests basic host reachability and maps the network path using ping and traceroute.

### What This Checks

- **Ping** — ICMP round-trip latency (min/avg/max), packet loss, host reachability
- **Traceroute** — Hop-by-hop network path, per-hop latency, unreachable hops

### Usage

```bash
node ./src/index.js -p ./playbooks/network-connectivity-test.md --target google.com
```
