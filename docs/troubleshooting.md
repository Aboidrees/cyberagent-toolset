# Troubleshooting

## Common errors

### nmap: requires root privileges

```TEXT
nmap error: Root privileges required for this scan type.
```

**Cause:** The playbook uses `-sS` (SYN scan) which requires raw socket access.

**Fix:** Use `-sT` (TCP connect scan) instead — it does not require root and works on all platforms:

```yaml
- name: Port Scan
  uses: nmap.scan
  with:
    flags: "-sT -Pn --top-ports 1000"
```

---

### nmap: command not found

```TEXT
Error: nmap not available on this system
```

**Fix:** Install nmap — see [Installation](installation.md).

---

### Operation timed out

```TEXT
Error: Step Name timed out after 10000ms
```

**Cause:** The step's timeout was too short for network conditions, or the target is slow / unreachable.

**Fix:** Increase the timeout at the step level or globally:

```yaml
# Step level (takes priority)
- name: Port Scan
  uses: nmap.scan
  with:
    flags: "-sT --top-ports 1000"
    timeoutMs: 300000   # 5 minutes
```

```bash
# Global CLI flag
node src/index.js -p playbooks/web-basic-recon.yaml --target example.com --timeout 30000
```

---

### DNS resolution failed

```TEXT
Error: getaddrinfo ENOTFOUND example.invalid
```

**Cause:** The target hostname does not exist or DNS is unavailable.

**Fix:**

- Verify the hostname is correct and publicly resolvable.
- Check your internet connection: `ping 8.8.8.8`
- Try `nslookup example.com` to test DNS separately.

---

### HTTP connection refused

```TEXT
Error: connect ECONNREFUSED
```

**Cause:** Nothing is listening on the target port (port is closed or firewall blocked).

**Fix:** This is expected for hosts that don't run a web server on that port. It is reported as a failed step but does not stop the playbook. If you expect the service to be up, verify with:

```bash
curl -I https://example.com
```

---

### TLS connect timeout

```TEXT
Error: TLS connect timeout after 12000ms
```

**Cause:** The host does not have TLS on port 443, the port is filtered, or the host is behind a firewall.

**Fix:** Check if HTTPS is actually available. If testing a non-standard TLS port, set `port` in the step options:

```yaml
- name: TLS on custom port
  uses: tls.inspect
  with:
    port: 8443
    timeoutMs: 15000
```

---

### crt.sh subdomain enumeration timeout

```TEXT
Error: timeout of 15000ms exceeded
```

**Cause:** crt.sh can be slow under load.

**Fix:** Increase the timeout in the playbook step:

```yaml
- name: Subdomains
  uses: subdomains.passive
  with:
    sources: ["crtsh"]
    timeoutMs: 30000
```

---

### Invalid target error

```TEXT
Error: Invalid target "example.com; rm -rf /": contains forbidden characters.
```

**Cause:** The target string contains shell metacharacters. This is the injection protection working correctly.

**Fix:** Use a plain hostname, IP address, or CIDR range:

- ✅ `example.com`
- ✅ `192.168.1.1`
- ✅ `192.168.1.0/24`
- ❌ `example.com; command`

---

### traceroute not found

```TEXT
Error: traceroute not available on this system. Install the traceroute package.
```

**Fix:** Install traceroute — see [Installation](installation.md).

---

## MCP-specific issues

### Claude doesn't see recon tools after restart

1. Verify the path in `claude_desktop_config.json` is the **absolute** path to `src/mcp-server.js`.
2. Test it manually: `node /absolute/path/to/src/mcp-server.js`
   - Expected stderr: `Loaded 9 extensions (23 executors), 13 playbooks`
3. Check Claude Desktop logs on macOS: `~/Library/Logs/Claude/`

### "Cannot find module" on MCP server start

Run `npm install` inside the project directory. The `node_modules/` folder must be present.

### MCP tool calls return empty results or garbled JSON

**Cause:** Something in the project wrote to stdout (not stderr) during execution. The MCP stdio transport uses stdout exclusively for JSON-RPC — any `console.log` call corrupts it.

**Fix:** All logging in this project goes to stderr. If you add custom executors, use `process.stderr.write()` or `console.error()` — never `console.log()`.

---

## Performance tuning

### Slow nmap scans

```bash
# Use T4 timing (aggressive) on reliable networks
flags: "-sT -T4 --top-ports 100"

# Scan fewer ports
flags: "-sT -Pn --top-ports 100"

# Specific ports only
flags: "-sT -Pn -p 80,443,8080,8443"
```

### Reduce overall run time

- Use `quick-web-recon` for a fast first pass instead of `comprehensive-web-recon`.
- Set `--timeout 10000` to cap slow steps.
- Reduce `maxHops` for traceroute: most targets are within 15 hops.

### Batch multiple targets

```bash
for target in app.example.com api.example.com admin.example.com; do
  node src/index.js -p playbooks/quick-web-recon.yaml --target "$target"
done
```

---

## Security notes

### Why execFile instead of exec?

All shell-calling executors (nmap, ping, traceroute) use `execFile` rather than `exec`. This means the target is passed as a separate argument array — the shell never interprets it. A target like `example.com; rm -rf /` is rejected by the validator before it reaches any system call, and even if it weren't, `execFile` would pass the whole string as a literal argument to nmap, not to a shell.

### Why validate every executor?

The `validateTarget` function in `src/utils/validate.js` runs at the entry point of every executor. This means validation happens whether the tool is called from the CLI, the MCP server, or directly in code — there's no path that bypasses it.

### TLS rejectUnauthorized: false

The TLS executor connects with `rejectUnauthorized: false` so it can inspect self-signed and expired certificates (common in internal infrastructure). This does **not** mean the connection is safe — it means the executor intentionally tolerates invalid certs to report on them. Evaluate the returned `valid_to`, `issuer`, and cipher fields yourself.
