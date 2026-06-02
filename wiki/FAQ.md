# FAQ

**Does it work without any API keys?**
Yes. All executors run keyless; keys (Shodan, NVD, AbuseIPDB) only add enrichment.

**Where do reports go?**
`runs/` as JSON + Markdown. Export to PDF/DOCX/HTML with `report` ([[Automation]]).

**Can I limit it to passive checks?**
Run passive playbooks (e.g. `email-security-assessment`). Every executor's posture
is shown by the `cats_capabilities` MCP tool.

**Does it do exploitation / post-exploitation?**
No. The lifecycle covers reconnaissance, scanning, and read-only gaining-access
(exposure detection). Maintaining-access and covering-tracks are out of scope by
design.

**How do I add a capability?**
Create a local extension or `npm install cyberagent-ext-<name>` — see [[Extensions]].

**Do playbooks change when capabilities are re-organized?**
No. Playbooks reference stable `uses:` keys; the phase/domain taxonomy is metadata
and never changes a key.

**Is the legacy `.md` playbook format still supported?**
Yes, for backward compatibility — but new playbooks should be `.yaml`.
