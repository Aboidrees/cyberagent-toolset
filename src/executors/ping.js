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
function getPingInvocation(target, count, osInfo) {
  if (osInfo.isWindows) {
    return ['ping', ['-n', String(count), target]];
  }
  // macOS and Linux both support: ping -c <count> <target>
  return ['ping', ['-c', String(count), target]];
}

/**
 * Ping a target host and return packet loss / latency statistics.
 */
export async function ping(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const count = opts.count || 4;
  const timeoutMs = opts.timeoutMs || 30000;

  const pingAvailable = await isCommandAvailable('ping');
  if (!pingAvailable) {
    throw new Error('Ping command not available on this system');
  }

  const osInfo = getOSInfo();
  const [cmd, args] = getPingInvocation(cleanTarget, count, osInfo);

  try {
    const { stdout, stderr } = await pexecFile(cmd, args, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
    });

    const stats = parsePingOutput(stdout, osInfo);

    return {
      command: `${cmd} ${args.join(' ')}`,
      raw: stdout,
      stderr: stderr || null,
      target: cleanTarget,
      count,
      os: osInfo.platform,
      stats,
    };
  } catch (e) {
    const stdout = e?.stdout || '';
    const stderr = e?.stderr || '';

    if (stderr.includes('Name or service not known') || stderr.includes('cannot resolve')) {
      throw new Error(
        `Ping failed: Unable to resolve hostname '${cleanTarget}'\n` +
        `Command: ${cmd} ${args.join(' ')}\nError: ${stderr}`
      );
    }

    if (stderr.includes('Network is unreachable') || stdout.includes('100% packet loss')) {
      throw new Error(
        `Ping failed: Network unreachable or 100% packet loss\n` +
        `Command: ${cmd} ${args.join(' ')}\nOutput: ${stdout}`
      );
    }

    throw new Error(
      `Ping error. cmd="${cmd} ${args.join(' ')}"\n` +
      `stdout: ${stdout}\nstderr: ${stderr}\nerror: ${e.message}`
    );
  }
}

// Parse ping output to extract statistics
function parsePingOutput(output, osInfo) {
  const stats = {
    packetsTransmitted: 0,
    packetsReceived: 0,
    packetLoss: 0,
    minTime: null,
    maxTime: null,
    avgTime: null,
  };

  try {
    if (osInfo.isWindows) {
      const lossMatch = output.match(/Lost = (\d+)/);
      const sentMatch = output.match(/Sent = (\d+)/);
      const receivedMatch = output.match(/Received = (\d+)/);
      const avgMatch = output.match(/Average = (\d+)ms/);

      if (sentMatch) stats.packetsTransmitted = parseInt(sentMatch[1]);
      if (receivedMatch) stats.packetsReceived = parseInt(receivedMatch[1]);
      if (lossMatch && sentMatch) {
        stats.packetLoss = Math.round(
          (parseInt(lossMatch[1]) / parseInt(sentMatch[1])) * 100
        );
      }
      if (avgMatch) stats.avgTime = parseFloat(avgMatch[1]);
    } else {
      const statsMatch = output.match(
        /(\d+) packets transmitted, (\d+) (?:packets )?received, .*?(\d+(?:\.\d+)?)% packet loss/
      );
      if (statsMatch) {
        stats.packetsTransmitted = parseInt(statsMatch[1]);
        stats.packetsReceived = parseInt(statsMatch[2]);
        stats.packetLoss = parseFloat(statsMatch[3]);
      }

      const timingMatch = output.match(
        /min\/avg\/max\/stddev = ([\d.]+)\/([\d.]+)\/([\d.]+)/
      );
      if (timingMatch) {
        stats.minTime = parseFloat(timingMatch[1]);
        stats.avgTime = parseFloat(timingMatch[2]);
        stats.maxTime = parseFloat(timingMatch[3]);
      }
    }
  } catch {
    // Non-fatal — return partial stats
  }

  return stats;
}
