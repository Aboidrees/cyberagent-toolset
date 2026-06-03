# CyberAgentToolSet (CATS)

An MCP server + CLI that orchestrates **authorized** security assessments across
the attack lifecycle (reconnaissance · scanning · gaining-access) via installable
**extensions**.

> ⚠️ **Authorized assessment only.** Active checks send traffic to the target. Only
> run them against assets you own or are explicitly authorized to test.

## Start here

- [[Installation]] — prerequisites and setup
- [[Quick Start]] — your first scan in 5 minutes
- [[User Guide]] — scenario-driven walkthrough of every use case

## Using it

- [[CLI Reference]] — `run` · `diff` · `watch` · `schedule` · `report`
- [[Playbooks]] — the YAML workflows and how to write them
- [[Executors]] — the 43 capabilities by phase / domain
- [[API Keys]] — Shodan, NVD, AbuseIPDB, webhooks (all optional)
- [[Automation]] — diffing, watchlists, scheduling, report export
- [[MCP Integration]] — drive it from Claude

## Extending it

- [[Extensions]] — the extension model; write or install one
- [[Architecture]] — taxonomy, catalog, plugin contract

## Help

- [[Troubleshooting]]
- [[FAQ]]

---

CATS is keyless by default. Capabilities are organized **domain-first** and tagged
by **phase** (reconnaissance / scanning / gaining-access) and **posture** (passive /
active). `maintaining-access` and `covering-tracks` are vocabulary only — out of
scope by design (no post-exploitation or anti-forensics).
