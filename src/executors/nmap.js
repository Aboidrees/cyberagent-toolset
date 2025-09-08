import { exec } from 'child_process';
import { promisify } from 'util';
const pexec = promisify(exec);

// Run an nmap scan on the target using the supplied flags.
export async function scanNmap(target, opts = {}) {
  // Use non-privileged scan by default (-sT instead of -sS)
  const flags = opts.flags || '-sT -Pn --top-ports 1000';
  const cmd = `nmap ${flags} ${target}`;
  
  console.log(`[DEBUG] Running nmap command: ${cmd}`);
  
  try {
    // Ensure timeout is a number
    const timeoutMs = typeof opts.timeoutMs === 'string' ? parseInt(opts.timeoutMs, 10) : opts.timeoutMs;
    const timeout = timeoutMs || 5 * 60 * 1000;
    
    const { stdout, stderr } = await pexec(cmd, {
      timeout: timeout,
      maxBuffer: 10 * 1024 * 1024
    });
    
    console.log(`[DEBUG] nmap completed successfully`);
    
    return { 
      command: cmd, 
      raw: stdout,
      stderr: stderr || null,
      target: target,
      flags: flags
    };
  } catch (e) {
    const stdout = e?.stdout || '';
    const stderr = e?.stderr || '';
    
    // Check for common privilege errors and provide helpful guidance
    if (stderr.includes('requires root privileges')) {
      const errorMsg = `nmap error: Root privileges required for scan type.\n` +
        `Tip: Use '-sT' instead of '-sS' for non-privileged TCP connect scans.\n` +
        `Command: ${cmd}\nError: ${stderr}`;
      console.log(`[DEBUG] nmap privilege error: ${errorMsg}`);
      throw new Error(errorMsg);
    }
    
    const errorMsg = `nmap error. cmd="${cmd}"\nstdout: ${stdout}\nstderr: ${stderr}\nerror: ${e.message}`;
    console.log(`[DEBUG] nmap failed: ${errorMsg}`);
    throw new Error(errorMsg);
  }
}