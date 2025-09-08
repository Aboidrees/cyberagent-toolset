import os from 'os';

// OS detection utility for choosing appropriate shell commands
export function getOSInfo() {
  const platform = os.platform();
  const type = os.type();
  const release = os.release();
  
  return {
    platform,
    type,
    release,
    isWindows: platform === 'win32',
    isMacOS: platform === 'darwin',
    isLinux: platform === 'linux',
    isUnix: platform !== 'win32'
  };
}

// Check if command is available on current OS
export async function isCommandAvailable(command) {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const pexec = promisify(exec);
  
  const osInfo = getOSInfo();
  
  try {
    if (osInfo.isWindows) {
      await pexec(`where ${command}`, { timeout: 5000 });
    } else {
      await pexec(`which ${command}`, { timeout: 5000 });
    }
    return true;
  } catch {
    return false;
  }
}

export default {
  getOSInfo,
  isCommandAvailable
};
