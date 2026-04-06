import { execFile } from 'child_process';
import { promisify } from 'util';
import { getOSInfo, isCommandAvailable } from '../utils/os.js';
import { validateTarget } from '../utils/validate.js';

const pexecFile = promisify(execFile);

/**
 * Build [command, argsArray] for the current OS.
 * Returns separate command + args so execFile can be used safely
 * (no shell interpolation of the target value).
 */
function getTracerouteInvocation(target, maxHops, osInfo) {
  if (osInfo.isWindows) {
    // tracert -h <maxHops> -d <target>  (-d = no DNS resolution, faster)
    return ['tracert', ['-h', String(maxHops), '-d', target]];
  }
  // macOS and Linux: traceroute -m <maxHops> -n <target>  (-n = no DNS, faster)
  return ['traceroute', ['-m', String(maxHops), '-n', target]];
}

/**
 * Perform a traceroute to a target and return hop-by-hop path info.
 */
export async function traceroute(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const maxHops = opts.maxHops || 30;
  const timeoutMs = opts.timeoutMs || 60000;

  const osInfo = getOSInfo();
  const traceCommand = osInfo.isWindows ? 'tracert' : 'traceroute';

  const traceAvailable = await isCommandAvailable(traceCommand);
  if (!traceAvailable) {
    throw new Error(
      `${traceCommand} not available on this system. ` +
      `Install the traceroute package (e.g. apt install traceroute).`
    );
  }

  const [cmd, args] = getTracerouteInvocation(cleanTarget, maxHops, osInfo);

  try {
    const { stdout, stderr } = await pexecFile(cmd, args, {
      timeout: timeoutMs,
      maxBuffer: 2 * 1024 * 1024,
    });

    const hops = parseTracerouteOutput(stdout, osInfo);

    return {
      command: `${cmd} ${args.join(' ')}`,
      raw: stdout,
      stderr: stderr || null,
      target: cleanTarget,
      maxHops,
      os: osInfo.platform,
      hops,
      hopCount: hops.length,
    };
  } catch (e) {
    const stdout = e?.stdout || '';
    const stderr = e?.stderr || '';

    if (
      stderr.includes('Name or service not known') ||
      stderr.includes('cannot resolve')
    ) {
      throw new Error(
        `Traceroute failed: Unable to resolve hostname '${cleanTarget}'\n` +
        `Command: ${cmd} ${args.join(' ')}\nError: ${stderr}`
      );
    }

    if (stderr.includes('Network is unreachable')) {
      throw new Error(
        `Traceroute failed: Network unreachable\n` +
        `Command: ${cmd} ${args.join(' ')}\nError: ${stderr}`
      );
    }

    // Return partial results if traceroute timed out mid-run
    if (stdout && stdout.length > 0) {
      const hops = parseTracerouteOutput(stdout, osInfo);
      return {
        command: `${cmd} ${args.join(' ')}`,
        raw: stdout,
        stderr: stderr || null,
        target: cleanTarget,
        maxHops,
        os: osInfo.platform,
        hops,
        hopCount: hops.length,
        timeout: true,
        error: e.message,
      };
    }

    throw new Error(
      `Traceroute error. cmd="${cmd} ${args.join(' ')}"\n` +
      `stdout: ${stdout}\nstderr: ${stderr}\nerror: ${e.message}`
    );
  }
}

// Parse traceroute output into structured hop objects
function parseTracerouteOutput(output, osInfo) {
  const hops = [];
  const lines = output.split('\n');

  try {
    for (const line of lines) {
      const hopMatch = line.match(/^\s*(\d+)\s+(.+)/);
      if (!hopMatch) continue;

      const hopNumber = parseInt(hopMatch[1]);
      const hopData = hopMatch[2].trim();

      if (osInfo.isWindows) {
        const timingMatches = hopData.match(/(\d+)\s*ms/g);
        const ipMatch = hopData.match(/\[?(\d+\.\d+\.\d+\.\d+)\]?/);
        const hostnameMatch = hopData.match(/^\s*([^\[\d\s]+)/);

        hops.push({
          number: hopNumber,
          hostname: hostnameMatch ? hostnameMatch[1].trim() : null,
          ip: ipMatch ? ipMatch[1] : null,
          times: timingMatches
            ? timingMatches.map(t => parseFloat(t.replace(/\s*ms/, '')))
            : [],
          rawLine: line.trim(),
        });
      } else {
        const ipMatch = hopData.match(/\((\d+\.\d+\.\d+\.\d+)\)/);
        const hostnameMatch = hopData.match(/^([^\s(]+)/);
        const timingMatches = hopData.match(/([\d.]+)\s*ms/g);

        const hop = {
          number: hopNumber,
          hostname: hostnameMatch ? hostnameMatch[1] : null,
          ip: ipMatch ? ipMatch[1] : null,
          times: timingMatches
            ? timingMatches.map(t => parseFloat(t.replace(/\s*ms/, '')))
            : [],
          rawLine: line.trim(),
        };

        if (
          hopData.includes('* * *') ||
          hopData.includes('Request timed out')
        ) {
          hop.timeout = true;
        }

        hops.push(hop);
      }
    }
  } catch {
    // Non-fatal — return whatever was parsed
  }

  return hops;
}
