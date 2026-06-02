# Architecture — CyberAgentToolSet (CATS)

CyberAgentToolSet is an MCP server + CLI that orchestrates authorized security
assessments across the attack lifecycle. Capabilities ship as **extensions**
(domain modules) that the core discovers, classifies, runs, and aggregates into
reports.

> Authorized assessment only. The engine covers **Reconnaissance**, **Scanning**,
> and read-only **Gaining Access** (exposure detection). **Maintaining Access** and
> **Covering Tracks** are part of the vocabulary but **out of scope by design** —
> the tool does not implement post-exploitation or anti-forensics.

---

## 1. Classification model

Every executor is classified on four axes (declared as metadata, not folder paths):

| Axis | Values |
| ---- | ------ |
| **phase** | `reconnaissance` · `scanning` · `gaining-access` *(`maintaining-access`, `covering-tracks` reserved, unused)* |
| **posture** | `passive` (no packets to target) · `active` (direct contact) |
| **domain** | `dns` · `whois` · `email` · `ip-intel` · `threat-intel` · `network` · `web` · `tls` · `cloud` |
| **targetTypes** | `domain` · `ip` · `cidr` · `url` · `email` (which inputs the executor accepts) |

The `uses:` key (e.g. `dns.resolve`) is a **stable logical id** and the API
contract for playbooks. It is *decoupled* from the taxonomy — re-classifying an
executor never changes its key, so playbooks never churn.

---

## 2. Extensions = domain modules

Code is organized **domain-first** (cohesion: all `http.*` logic shares a client,
URL builder, and signatures, so it lives in one extension even though some
executors are `scanning` and some are `gaining-access`). Phase/posture are facets
computed from metadata, surfaced as views in the MCP tool list and reports.

```
extensions/
  <domain>/
    index.js          # default-exports the Extension Descriptor (the "manifest")
    src/*.js          # capability implementations + _shared helpers
    report.js         # owns findings extraction for this domain's executors
```

### Extension Descriptor (the manifest)

`extensions/<domain>/index.js` default-exports:

```js
export default {
  name: 'dns',
  version: '1.0.0',
  description: 'DNS reconnaissance — records, reverse/PTR, passive subdomains.',
  executors: [
    {
      uses: 'dns.resolve',
      phase: 'reconnaissance',
      posture: 'passive',
      targetTypes: ['domain', 'ip'],
      summary: 'Resolve DNS records (A/AAAA/CNAME/NS/MX/TXT/PTR/SOA).',
      run: resolveDNS,            // (target, opts, ctx) => data
      inputSchema: { /* JSON-schema-ish props for the MCP tool */ },
    },
    // ...
  ],
  permissions: { network: ['dns', 'https'], env: [], bins: [] },
  report: { findings },           // findings(stepOutput) => Finding[]
};
```

- **`run(target, opts, ctx)`** — `ctx` injects shared services (`validateTarget`,
  …). Local extensions may import `#sdk` directly and ignore `ctx`; npm plugins use
  `ctx` so they need no access to core internals.
- **`permissions`** — declared up front; the core can enforce a passive-only mode
  and surfaces what an extension touches (network egress, env keys, external bins).
- **`report.findings`** — owns severity extraction for this domain. Moves the old
  monolithic per-executor logic out of `utils/findings.js` (which becomes a thin
  aggregator).

---

## 3. The core

The core shrinks to an engine + registry + safety + aggregation. It no longer
hardcodes executors.

- **`src/sdk.js`** — shared services (`validateTarget`, `validateNmapFlags`, …),
  re-exported via the package `imports` map as `#sdk`.
- **`src/extensions/loader.js`** — `loadCatalog()` discovers descriptors and builds:
  - `registry` : `uses` → `run`
  - `executors`: flat metadata list (phase/posture/domain/targetTypes/summary)
  - `reportersByUses`: `uses` → owning extension's `report`
  - grouping views: `byPhase`, `byDomain`
  - collision + schema validation. Memoized (loaded once).
- **`src/runner.js`** — uses `catalog.registry[uses]`; everything else (templating,
  parallel steps, timeouts, report writing) unchanged.
- **`src/mcp-server.js`** — builds one MCP tool per executor from `catalog.executors`
  (no more 23-case switch); dispatches via `catalog.registry`.
- **`src/utils/findings.js`** — generic `data.findings[]` handling + delegates the
  rest to `reportersByUses`.

### Discovery

1. **Local** (out of the box): every `extensions/<dir>/index.js`.
2. **NPM plugins** (day one): installed packages named `cyberagent-ext-*` /
   `@cyberagent/ext-*`, or whose `package.json` `keywords` include
   `cyberagent-extension`. Same descriptor contract; shared services via `ctx`.

---

## 4. Capabilities this unlocks

- **Passive-only / safe mode** — run only `posture: passive` checks; enforced via
  `permissions`.
- **Target-aware assembly** — auto-select executors whose `targetTypes` match the
  given target (IP → network/ip; domain → dns/email/web).
- **Phase-grouped reports & tool listing** — derived from metadata.
- **Third-party extensions** — `npm i cyberagent-ext-nuclei` auto-registers.

(These build on the metadata; the v1 refactor lands the structure and a couple of
the views; the rest follow incrementally.)

---

## 5. Migration (kept green throughout)

`uses:` keys and playbook YAML stay identical, so the 23-executor self-test is the
regression oracle at every stage:

1. SDK + `#sdk` import map + loader/catalog.
2. Move executors into `extensions/<domain>/` with descriptors + report modules.
3. Rewire `runner.js` and `mcp-server.js` to the catalog; thin `findings.js`.
4. NPM-plugin discovery.
5. Rename `mcp-recon-runner` → `cyberagent-toolset` (CATS), tool prefix `cats_`.
