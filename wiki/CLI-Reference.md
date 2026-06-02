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
