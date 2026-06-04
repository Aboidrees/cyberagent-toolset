# CLI Reference

`node src/index.js <command>` (or the `cyberagent` bin if installed). `run` is the
default command, so the bare `-p … --target …` form works.

## run (default)

```bash
node src/index.js -p <playbook.yaml> --target <host> [--var k=v] [--out ./runs] [--timeout ms]
```

Runs a playbook. `--var` overrides playbook variables (repeatable). `--target` is
shorthand for `--var target=<host>`.

## diff

```bash
node src/index.js diff <a.json> <b.json> [--out diff.md]
```

Compares two run JSONs — new/removed ports, subdomains, DNS records, certificate
changes, and security findings. **Exits non-zero when something changed** (handy
for monitoring/CI).

## watch

```bash
node src/index.js watch --list <watchlist.yaml> [--out ./runs] [--timeout ms]
```

Batch-runs every target × playbook in a watchlist. See [[Automation]].

## schedule

```bash
node src/index.js schedule --playbook <id> --target <host> --cron "<expr>" [--now]
```

Runs a playbook on a cron schedule (stays running). New findings fire webhooks if
configured.

## report

```bash
node src/index.js report <run.json> --format pdf|docx|html [--out file] [--company "Name"]
```

Exports a branded assessment report with executive summary, risk matrix, and
findings table.

## help

```bash
node src/index.js --help
```

## auto

```bash
node src/index.js auto --target <host> [--phase reconnaissance|scanning|gaining-access|all] [--passive]
```

Infers the target type (domain / IP / CIDR / URL) and runs every applicable
executor — "run all applicable recon" with no hand-written playbook.

## capabilities (alias: list)

```bash
node src/index.js capabilities [--json]
```

Prints every executor grouped by phase / posture / domain. Mirrors the MCP
`cats_capabilities` tool.

## permissions (alias: perms)

```bash
node src/index.js permissions [--json]
```

Shows each extension's declared `network` / `env` / `bins`. Set
`CATS_STRICT_PERMISSIONS=1` to make undeclared env/bin access throw at runtime.

## assess

A stateful, agent-style assessment: results feed an entity graph and a pivot
engine that ranks the next best actions; the report correlates findings (CVE ×
EPSS). Mirrors the MCP `cats_assess_*` tools.

```bash
node src/index.js assess start <target> --full        # drive the WHOLE assessment in one command
node src/index.js assess start <target> [--passive]   # → id + ranked next actions
node src/index.js assess run <id> --top 5             # run top suggestions; new pivots surface
node src/index.js assess run <id> --uses smb.probe --on 1.2.3.4   # run a specific executor
node src/index.js assess next <id> [--top 10]         # show ranked next actions
node src/index.js assess report <id> [--json] [--out report.md]
node src/index.js assess report <id> --format pdf|docx|html [--out f] [--company X]   # export
node src/index.js assess diff <idA> <idB> [--json] [--out diff.md]   # compare over time
node src/index.js assess list                         # all saved assessments
```

## dashboard

Local browser UI — browse assessments and runs, drive an assessment
(start → run → prioritized report), and diff two runs. Built on Node's `http`
(no new dependency) and **localhost-bound** (it can trigger active scans).

```bash
node src/index.js dashboard [--port 7878] [--host 127.0.0.1]   # → http://127.0.0.1:7878
```

## Passive-only / safe mode

Add `--passive` to `run` or `auto` (or the `passive` option on the MCP `cats_run`
/ `cats_run_multi` / `cats_play__` tools) to skip every **active** executor — no
packets reach the target host. Skipped steps show as `⏭️ Skipped` in the report.
