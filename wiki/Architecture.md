# Architecture

CATS is an engine + catalog that discovers **extensions** and runs them. Full
design lives in the repo's `docs/architecture.md`; this is the summary.

## Classification model

Every executor is tagged with metadata (decoupled from its `uses:` key, which
stays stable so playbooks never churn):

| Axis | Values |
| ---- | ------ |
| **phase** | `reconnaissance` · `scanning` · `gaining-access` (*maintaining-access* / *covering-tracks* reserved, unused) |
| **posture** | `passive` (no packets to target) · `active` |
| **domain** | dns · whois · email · ip-intel · threat-intel · network · web · tls · cloud |
| **targetTypes** | domain · ip · cidr · url · email |

## Domain-first layout

Code is organized by domain (cohesion — all `http.*` shares one client), under
`extensions/<domain>/`. Phase/posture are facets computed from metadata and
surfaced as views.

## The core

- `src/sdk.js` — shared services, exposed as `#sdk` and injected as `ctx`.
- `src/extensions/loader.js` — `loadCatalog()` discovers descriptors (local +
  npm `cyberagent-ext-*`) and builds the `uses → run` registry, executor metadata,
  report owners, and phase/domain views. Memoized.
- `src/runner.js` — runs playbooks via `catalog.registry`; parallel steps,
  templating, timeouts, report writing.
- `src/mcp-server.js` — generates one `cats_<uses>` tool per executor + a
  `cats_capabilities` tool; dispatches generically through the catalog.
- `src/utils/findings.js` — thin aggregator; domain severity logic lives in each
  extension's `report.js`.

## Discovery

1. **Local**: every `extensions/<dir>/index.js`.
2. **NPM plugins**: packages named `cyberagent-ext-*` / `@cyberagent/ext-*`.

Both use the same descriptor contract. See [[Extensions]].

## Out of scope by design

The tool does not implement post-exploitation (`maintaining-access`) or
anti-forensics (`covering-tracks`). Those remain vocabulary only.
