# Extensions

Capabilities ship as **extensions** — domain modules the engine discovers and
loads. Two sources, same contract:

1. **Local** (out of the box): every `extensions/<domain>/index.js`.
2. **NPM plugins** (day one): packages named `cyberagent-ext-*` / `@cyberagent/ext-*`
   installed in the project — auto-discovered.

## Anatomy

```
extensions/<domain>/
  index.js     # default-exports the descriptor (the manifest)
  src/*.js     # capability implementations
  report.js    # owns this domain's findings extraction (optional)
```

## The descriptor

```js
import { myAction } from './src/run.js';

export default {
  name: 'mytool',
  version: '1.0.0',
  domain: 'mytool',
  description: 'What this extension does.',
  permissions: { network: [], env: [], bins: ['mytool'] },
  executors: [
    {
      uses: 'mytool.action',         // stable id used in playbooks
      phase: 'scanning',             // reconnaissance | scanning | gaining-access
      posture: 'active',             // passive | active
      targetTypes: ['domain', 'ip'],
      summary: 'One-line summary.',
      run: myAction,                 // (target, opts, ctx) => data
      inputSchema: { target: { type: 'string' } },
    },
  ],
  // Optional: own your findings.
  // report: { findings: (output) => [{ severity: 'high', message: '...' }] },
};
```

## Shared services

Local extensions import `#sdk` (`import { validateTarget } from '#sdk'`). The same
services are injected as the third `ctx` argument of every `run(target, opts, ctx)`
— npm plugins use `ctx.validateTarget` and need no access to core internals.

## Ship it as a plugin

Publish the descriptor as `cyberagent-ext-<name>` (default-export from `main`).
`npm install cyberagent-ext-<name>` and it auto-registers — no code changes.

## Rules

- Call `validateTarget` (or `ctx.validateTarget`) before contacting a target.
- Use `execFile`, never `exec`, for external binaries.
- Declare what you touch in `permissions` (network egress, env keys, bins).

See [[Architecture]] for the catalog/loader internals.
