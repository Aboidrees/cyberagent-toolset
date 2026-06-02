# Automation

## Diff two runs

```bash
node src/index.js diff runs/old.json runs/new.json [--out diff.md]
```
Highlights new/removed open ports, subdomains, DNS records, certificate changes,
and new/resolved findings. Non-zero exit on change.

## Watchlist (batch)

`watchlists/example.yaml`:
```yaml
vars: { scheme: https }
targets:
  - host: example.com
    playbooks: [quick-web-recon, web-headers-assessment]
  - host: api.example.com
    playbooks: [api-cloud-recon]
```
```bash
node src/index.js watch --list watchlists/example.yaml
```

## Scheduled scanning

```bash
node src/index.js schedule --playbook quick-web-recon --target example.com --cron "0 8 * * 1"
```
Runs on the cron schedule (stays running). Combine with webhooks to get notified
when new findings appear.

## Notifications

Set in `.env` (see [[API Keys]]):
```
SLACK_WEBHOOK_URL=...
WEBHOOK_URL=...
NOTIFY_ON_SEVERITY=high,critical   # or "all"
```
A run summary is POSTed when findings meet the threshold.

## Report export

```bash
node src/index.js report runs/run.json --format pdf --out report.pdf --company "Acme"
```
PDF / DOCX / HTML, with executive summary, risk matrix, and findings table.
