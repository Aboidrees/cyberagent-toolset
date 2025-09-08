import { exec } from 'child_process';
import { promisify } from 'util';
import { getOSInfo, isCommandAvailable } from '../utils/os.js';

const pexec = promisify(exec);

// Get appropriate ping command for current OS
function getPingCommand(target, count = 4) {
  const osInfo = getOSInfo();
  
  if (osInfo.isWindows) {
    // Windows: ping -n count target
    return `ping -n ${count} ${target}`;
  } else {
    // Unix-like (macOS, Linux): ping -c count target
    return `ping -c ${count} ${target}`;
  }
}

// Ping a target using the appropriate OS command
export async function ping(target, opts = {}) {
  const count = opts.count || 4;
  const timeoutMs = opts.timeoutMs || 30000;
  
  // Check if ping is available
  const pingAvailable = await isCommandAvailable('ping');
  if (!pingAvailable) {
    throw new Error('Ping command not available on this system');
  }
  
  const osInfo = getOSInfo();
  const cmd = getPingCommand(target, count);
  
  console.log(`[DEBUG] Running ping command: ${cmd}`);
  console.log(`[DEBUG] OS detected: ${osInfo.platform} (${osInfo.type})`);
  
  try {
    const { stdout, stderr } = await pexec(cmd, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024
    });
    
    console.log(`[DEBUG] Ping completed successfully`);
    
    // Parse basic ping statistics
    const stats = parsePingOutput(stdout, osInfo);
    
    return {
      command: cmd,
      raw: stdout,
      stderr: stderr || null,
      target: target,
      count: count,
      os: osInfo.platform,
      stats: stats
    };
  } catch (e) {
    const stdout = e?.stdout || '';
    const stderr = e?.stderr || '';
    
    // Check for common ping errors
    if (stderr.includes('Name or service not known') || stderr.includes('cannot resolve')) {
      const errorMsg = `Ping failed: Unable to resolve hostname '${target}'\nCommand: ${cmd}\nError: ${stderr}`;
      console.log(`[DEBUG] Ping DNS resolution error: ${errorMsg}`);
      throw new Error(errorMsg);
    }
    
    if (stderr.includes('Network is unreachable') || stdout.includes('100% packet loss')) {
      const errorMsg = `Ping failed: Network unreachable or 100% packet loss\nCommand: ${cmd}\nOutput: ${stdout}`;
      console.log(`[DEBUG] Ping network error: ${errorMsg}`);
      throw new Error(errorMsg);
    }
    
    const errorMsg = `Ping error. cmd="${cmd}"\nstdout: ${stdout}\nstderr: ${stderr}\nerror: ${e.message}`;
    console.log(`[DEBUG] Ping failed: ${errorMsg}`);
    throw new Error(errorMsg);
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
    avgTime: null
  };
  
  try {
    if (osInfo.isWindows) {
      // Windows ping output parsing
      const lossMatch = output.match(/Lost = (\d+)/);
      const sentMatch = output.match(/Sent = (\d+)/);
      const receivedMatch = output.match(/Received = (\d+)/);
      const avgMatch = output.match(/Average = (\d+)ms/);
      
      if (sentMatch) stats.packetsTransmitted = parseInt(sentMatch[1]);
      if (receivedMatch) stats.packetsReceived = parseInt(receivedMatch[1]);
      if (lossMatch && sentMatch) {
        stats.packetLoss = Math.round((parseInt(lossMatch[1]) / parseInt(sentMatch[1])) * 100);
      }
      if (avgMatch) stats.avgTime = parseFloat(avgMatch[1]);
      
    } else {
      // Unix-like ping output parsing
      const statsMatch = output.match(/(\d+) packets transmitted, (\d+) (?:packets )?received, .*?(\d+(?:\.\d+)?)% packet loss/);
      if (statsMatch) {
        stats.packetsTransmitted = parseInt(statsMatch[1]);
        stats.packetsReceived = parseInt(statsMatch[2]);
        stats.packetLoss = parseFloat(statsMatch[3]);
      }
      
      const timingMatch = output.match(/min\/avg\/max\/stddev = ([\d.]+)\/([\d.]+)\/([\d.]+)/);
      if (timingMatch) {
        stats.minTime = parseFloat(timingMatch[1]);
        stats.avgTime = parseFloat(timingMatch[2]);
        stats.maxTime = parseFloat(timingMatch[3]);
      }
    }
  } catch (e) {
    console.log(`[DEBUG] Failed to parse ping statistics: ${e.message}`);
  }
  
  return stats;
}
