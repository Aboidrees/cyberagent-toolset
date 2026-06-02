---
id: email-security-assessment
title: Email Security Assessment
vars:
  target: "example.com"
steps:
  # Full email-auth posture in one pass: SPF, DMARC, DKIM, MTA-STS, BIMI
  - name: Email Security Posture
    uses: email.security
    with:
      selectors: ["default", "google", "selector1", "selector2", "k1", "mail"]
      # Generous step budget; each individual DNS lookup is capped internally
      # (dnsTimeoutMs, default 6s) so slow resolver responses can't hang it.
      timeoutMs: 20000

  # Raw TXT records for manual cross-checking
  - name: Root TXT Records
    uses: dns.resolve
    with:
      types: ["TXT"]
      timeoutMs: 15000

  - name: MX Records
    uses: dns.resolve
    with:
      types: ["MX"]
      timeoutMs: 15000
---

## Email Security Assessment for {{vars.target}}

Evaluates a domain's email authentication and anti-spoofing posture without
sending a single packet to the mail servers — every check is a passive DNS
lookup (plus one HTTPS fetch for the MTA-STS policy file).

### What This Checks

- **SPF** — presence, `include:` chain depth, and risky `+all` / `?all` qualifiers
- **DMARC** — policy strength (`p=none` is monitor-only), `rua`/`ruf` reporting, `pct`
- **DKIM** — key discovery across common selectors (Google, Microsoft, Mailchimp, etc.)
- **MTA-STS** — TXT record + enforced policy mode (`enforce` vs `testing`)
- **BIMI** — brand indicator record and logo reference

### Interpreting Results

Each sub-check returns a `findings` array with a severity. The top-level
`summary` gives an at-a-glance posture, and `findings` rolls every issue up into
one list for triage. A domain with no SPF and no DMARC is trivially spoofable.

### Usage

```bash
node ./src/index.js -p ./playbooks/email-security-assessment.md --var target=yourdomain.com
```
