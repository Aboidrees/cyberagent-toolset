# cyberagent-ext-starter

A minimal, copy-me template for building a **CyberAgentToolSet (CATS)** extension.
An extension is a small package that contributes one or more *executors* (recon
checks) to CATS. The engine discovers it automatically.

## What's here

```text
cyberagent-ext-starter/
├── index.js          # the descriptor (manifest) CATS reads
├── src/example.js    # one example executor (run(target, opts, ctx))
└── package.json      # name must start with cyberagent-ext-  (or @scope/cyberagent-ext-)
```

## The contract

- **`index.js`** default-exports a descriptor: `{ name, version, domain, description, permissions, executors[] }`.
- Each executor declares `uses` (stable id), `phase`, `posture`, `targetTypes`, `summary`, `inputSchema`, and a `run` function.
- **`run(target, opts, ctx)`** returns any JSON object. Include a `findings: [{ severity, message }]` array and CATS rolls it into the report.
- Use **`ctx`** (`ctx.validateTarget`, `ctx.env`, `ctx.requireBin`, severity helpers) instead of importing from the host — that keeps your plugin decoupled and lets the runtime enforce your declared `permissions`.

## Develop & test

```bash
# 1. Copy this folder, rename it, and edit package.json "name" to cyberagent-ext-<yourtool>.
# 2. Smoke-test the executor directly:
node -e 'import("./src/example.js").then(async ({ example }) => {
  console.log(await example("example.com", {}, { validateTarget: x => x }));
})'
```

To try it inside a CATS checkout, either:

- **Local:** drop the folder under the host repo's `extensions/`, or
- **npm link:** `npm link` here, then `npm link cyberagent-ext-<yourtool>` in the host — it auto-registers.

Verify it loaded:

```bash
node src/index.js capabilities        # your uses key should appear
node src/index.js permissions         # your declared permissions should appear
```

## Permissions

Declare every protocol, env var, and binary you touch in `permissions`. Running
the host with `CATS_STRICT_PERMISSIONS=1` turns any **undeclared** `ctx.env(KEY)`
or `ctx.requireBin(name)` access into a hard error — so third-party extensions
can't quietly reach for credentials or shell out to tools they didn't declare.

## Publish

```bash
npm publish --access public     # name must match cyberagent-ext-* / @cyberagent/ext-*
```

Once installed in a CATS project (`npm install cyberagent-ext-<yourtool>`), the
loader discovers and registers it on startup — no code changes in the host.

## License

MIT — adapt freely. Use responsibly; only assess systems you're authorized to test.
