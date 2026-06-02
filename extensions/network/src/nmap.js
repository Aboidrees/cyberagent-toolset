import { execFile } from 'child_process';
import { promisify } from 'util';
import { validateTarget, validateNmapFlags } from '#sdk';

const pexecFile = promisify(execFile);

/**
 * Run an nmap scan on the target using the supplied flags.
 * Uses execFile (not exec) so the target and flags are never interpreted
 * by a shell — eliminating command injection risk.
 */
export async function scanNmap(target, opts = {}) {
  const cleanTarget = validateTarget(target);

  const rawFlags = opts.flags || '-sT -Pn --top-ports 1000';
  const cleanFlags = validateNmapFlags(rawFlags);

  // Split flags into an array for execFile (no shell interpolation)
  const flagArgs = cleanFlags.split(/\s+/).filter(Boolean);
  const args = [...flagArgs, cleanTarget];

  const timeoutMs =
    typeof opts.timeoutMs === 'string'
      ? parseInt(opts.timeoutMs, 10)
      : opts.timeoutMs;
  const timeout = timeoutMs || 5 * 60 * 1000;

  try {
    const { stdout, stderr } = await pexecFile('nmap', args, {
      timeout,
      maxBuffer: 10 * 1024 * 1024,
    });

    return {
      command: `nmap ${args.join(' ')}`,
      raw: stdout,
      stderr: stderr || null,
      target: cleanTarget,
      flags: cleanFlags,
    };
  } catch (e) {
    const stdout = e?.stdout || '';
    const stderr = e?.stderr || '';

    if (stderr.includes('requires root privileges')) {
      throw new Error(
        `nmap error: Root privileges required for this scan type.\n` +
        `Tip: Use '-sT' instead of '-sS' for non-privileged TCP connect scans.\n` +
        `Command: nmap ${args.join(' ')}\nError: ${stderr}`
      );
    }

    throw new Error(
      `nmap error. cmd="nmap ${args.join(' ')}"\nstdout: ${stdout}\nstderr: ${stderr}\nerror: ${e.message}`
    );
  }
}
