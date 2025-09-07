import { exec } from 'child_process';
import { promisify } from 'util';
const pexec = promisify(exec);

// Run an nmap scan on the target using the supplied flags.
export async function scanNmap(target, opts = {}) {
  const flags = opts.flags || '-sV -Pn --top-ports 1000';
  const cmd = `nmap ${flags} ${target}`;
  try {
    const { stdout } = await pexec(cmd, {
      timeout: 5 * 60 * 1000,
      maxBuffer: 10 * 1024 * 1024
    });
    return { command: cmd, raw: stdout };
  } catch (e) {
    const raw = e?.stdout || e?.stderr || '';
    throw new Error(`nmap error. cmd="${cmd}"\n${raw}`);
  }
}