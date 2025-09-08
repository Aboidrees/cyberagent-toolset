---
title: Network Connectivity Testing
description: Test network connectivity with ping and traceroute
vars:
  target: google.com
steps:
  - name: Ping Test
    uses: network.ping
    with:
      count: 4
      timeoutMs: 10000
  - name: Traceroute Test
    uses: network.traceroute
    with:
      maxHops: 10
    #   timeoutMs: 30000
output:
  - json
  - markdown
---

This playbook tests network connectivity using ping and traceroute commands.

## Variables

- **target**: The target hostname or IP address to test (default: google.com)

## Network Connectivity Tests

### Ping Test

Test basic connectivity and response times. The ping test sends packets to verify the target is reachable and measures response times.

### Traceroute Test

Trace the network path to the target. The traceroute test maps the network path showing each hop between your system and the target.

## Results Summary

### Ping Statistics

- **Target**: {{vars.target}}
- **Packets Sent**: {{ping_results.packetsSent}}
- **Packets Received**: {{ping_results.packetsReceived}}
- **Packet Loss**: {{ping_results.packetLoss}}%
- **Average RTT**: {{ping_results.avgTime}}ms
- **Min RTT**: {{ping_results.minTime}}ms
- **Max RTT**: {{ping_results.maxTime}}ms

### Network Path

- **Total Hops**: {{traceroute_results.hopCount}}
- **Path Traced**: From local system to {{vars.target}}

### Detailed Hop Information

{{#each traceroute_results.hops}}
**Hop {{number}}**: {{hostname}} ({{ip}}) - Average: {{times}}ms
{{/each}}

---

**Test completed at**: {{timestamp}}
**Operating System**: {{traceroute_results.os}}
