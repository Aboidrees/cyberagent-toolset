import os from 'os';
import { execFile } from 'child_process';
import { promisify } from 'util';

const pexecFile = promisify(execFile);

/**
 * Return basic OS detection flags.
 */
export function getOSInfo() {
  const platform = os.platform();
  const type     = os.type();
  const release  = os.release();
  return {
    platform,
    type,
    release,
    isWindows: platform === 'win32',
    isMacOS:   platform === 'darwin',
    isLinux:   platform === 'linux',
    isUnix:    platform !== 'win32',
  };
}

/**
 * Check whether a CLI tool is available on PATH.
 *
 * Uses execFile (not exec) so the command name is never shell-interpolated.
 * Only 'which' / 'where' are ever called — both are safe fixed strings.
 */
export async function isCommandAvailable(command) {
  // Hard-block anything that isn't a plain alphanumeric tool name
  if (!/^[a-zA-Z0-9_-]+$/.test(command)) return false;

  const osInfo = getOSInfo();
  const checker = osInfo.isWindows ? 'where' : 'which';

  try {
    await pexecFile(checker, [command], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

export default { getOSInfo, isCommandAvailable };
