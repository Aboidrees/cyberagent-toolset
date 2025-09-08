import { exec } from 'child_process';
import { promisify } from 'util';
import { getOSInfo, isCommandAvailable } from '../utils/os.js';

const pexec = promisify(exec);

// Get appropriate traceroute command for current OS
function getTracerouteCommand(target, maxHops = 30) {
  const osInfo = getOSInfo();
  
  if (osInfo.isWindows) {
    // Windows: tracert -h max_hops -d target
    // -d = don't resolve hostnames to IP addresses (much faster)
    return `tracert -h ${maxHops} -d ${target}`;
  } else if (osInfo.isMacOS) {
    // macOS: traceroute -m max_hops -n target
    // -n = don't resolve hostnames to IP addresses (much faster)
    return `traceroute -m ${maxHops} -n ${target}`;
  } else {
    // Linux: traceroute -m max_hops -n target
    // -n = don't resolve hostnames to IP addresses (much faster)
    return `traceroute -m ${maxHops} -n ${target}`;
  }
}

// Traceroute to a target using the appropriate OS command
export async function traceroute(target, opts = {}) {
  const maxHops = opts.maxHops || 30;
  const timeoutMs = opts.timeoutMs || 60000; // Traceroute can take longer
  
  const osInfo = getOSInfo();
  
  // Check if traceroute/tracert is available
  const traceCommand = osInfo.isWindows ? 'tracert' : 'traceroute';
  const traceAvailable = await isCommandAvailable(traceCommand);
  if (!traceAvailable) {
    throw new Error(`${traceCommand} command not available on this system. Install traceroute package.`);
  }
  
  const cmd = getTracerouteCommand(target, maxHops);
  
  console.log(`[DEBUG] Running traceroute command: ${cmd}`);
  console.log(`[DEBUG] OS detected: ${osInfo.platform} (${osInfo.type})`);
  
  try {
    const { stdout, stderr } = await pexec(cmd, {
      timeout: timeoutMs,
      maxBuffer: 2 * 1024 * 1024 // Larger buffer for traceroute output
    });
    
    console.log(`[DEBUG] Traceroute completed successfully`);
    
    // Parse traceroute output
    const hops = parseTracerouteOutput(stdout, osInfo);
    
    return {
      command: cmd,
      raw: stdout,
      stderr: stderr || null,
      target: target,
      maxHops: maxHops,
      os: osInfo.platform,
      hops: hops,
      hopCount: hops.length
    };
  } catch (e) {
    const stdout = e?.stdout || '';
    const stderr = e?.stderr || '';
    
    // Check for common traceroute errors
    if (stderr.includes('Name or service not known') || stderr.includes('cannot resolve')) {
      const errorMsg = `Traceroute failed: Unable to resolve hostname '${target}'\nCommand: ${cmd}\nError: ${stderr}`;
      console.log(`[DEBUG] Traceroute DNS resolution error: ${errorMsg}`);
      throw new Error(errorMsg);
    }
    
    if (stderr.includes('Network is unreachable')) {
      const errorMsg = `Traceroute failed: Network unreachable\nCommand: ${cmd}\nError: ${stderr}`;
      console.log(`[DEBUG] Traceroute network error: ${errorMsg}`);
      throw new Error(errorMsg);
    }
    
    // If we have partial output, still return it as traceroute might timeout
    if (stdout && stdout.length > 0) {
      console.log(`[DEBUG] Traceroute timeout with partial results`);
      const hops = parseTracerouteOutput(stdout, osInfo);
      return {
        command: cmd,
        raw: stdout,
        stderr: stderr || null,
        target: target,
        maxHops: maxHops,
        os: osInfo.platform,
        hops: hops,
        hopCount: hops.length,
        timeout: true,
        error: e.message
      };
    }
    
    const errorMsg = `Traceroute error. cmd="${cmd}"\nstdout: ${stdout}\nstderr: ${stderr}\nerror: ${e.message}`;
    console.log(`[DEBUG] Traceroute failed: ${errorMsg}`);
    throw new Error(errorMsg);
  }
}

// Parse traceroute output to extract hop information
function parseTracerouteOutput(output, osInfo) {
  const hops = [];
  const lines = output.split('\n');
  
  try {
    if (osInfo.isWindows) {
      // Windows tracert output parsing
      for (const line of lines) {
        const hopMatch = line.match(/^\s*(\d+)\s+(.+)/);
        if (hopMatch) {
          const hopNumber = parseInt(hopMatch[1]);
          const hopData = hopMatch[2].trim();
          
          // Extract timing and IP information
          const timingMatches = hopData.match(/(\d+)\s*ms/g);
          const ipMatch = hopData.match(/\[?(\d+\.\d+\.\d+\.\d+)\]?/);
          const hostnameMatch = hopData.match(/^\s*([^\[\d\s]+)/);
          
          const hop = {
            number: hopNumber,
            hostname: hostnameMatch ? hostnameMatch[1].trim() : null,
            ip: ipMatch ? ipMatch[1] : null,
            times: timingMatches ? timingMatches.map(t => parseFloat(t.replace(/\s*ms/, ''))) : [],
            rawLine: line.trim()
          };
          
          hops.push(hop);
        }
      }
    } else {
      // Unix-like traceroute output parsing
      for (const line of lines) {
        const hopMatch = line.match(/^\s*(\d+)\s+(.+)/);
        if (hopMatch) {
          const hopNumber = parseInt(hopMatch[1]);
          const hopData = hopMatch[2].trim();
          
          // Extract hostname/IP and timing
          const ipMatch = hopData.match(/\((\d+\.\d+\.\d+\.\d+)\)/);
          const hostnameMatch = hopData.match(/^([^\s\(]+)/);
          const timingMatches = hopData.match(/([\d.]+)\s*ms/g);
          
          const hop = {
            number: hopNumber,
            hostname: hostnameMatch ? hostnameMatch[1] : null,
            ip: ipMatch ? ipMatch[1] : null,
            times: timingMatches ? timingMatches.map(t => parseFloat(t.replace(/\s*ms/, ''))) : [],
            rawLine: line.trim()
          };
          
          // Handle timeouts and unreachable hops
          if (hopData.includes('* * *') || hopData.includes('Request timed out')) {
            hop.timeout = true;
          }
          
          hops.push(hop);
        }
      }
    }
  } catch (e) {
    console.log(`[DEBUG] Failed to parse traceroute output: ${e.message}`);
  }
  
  return hops;
}
