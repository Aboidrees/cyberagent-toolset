import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { validateTarget } from '#sdk';
import { buildUrl } from './http.js';

const pexecFile = promisify(execFile);

/**
 * Headless-browser screenshot. Renders a target page with a headless Chrome /
 * Chromium / Edge and saves a PNG — useful for triage and report evidence.
 *
 * Degrades gracefully: if no headless-capable browser is found it returns a
 * no-op note rather than failing (same contract as `nuclei.scan`). No new npm
 * dependency — it drives an installed browser binary via `--headless=new`.
 *
 * ⚠️ Active — fetches the page. Authorized targets only.
 */

// PATH-resolvable names (Linux/Windows) + absolute app paths (macOS).
const PATH_CANDIDATES = ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable', 'chrome', 'msedge'];
const APP_CANDIDATES = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
];

async function onPath(name) {
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) return false;
  const checker = os.platform() === 'win32' ? 'where' : 'which';
  try { await pexecFile(checker, [name], { timeout: 5000 }); return true; } catch { return false; }
}

async function findBrowser(explicit) {
  const fromEnv = explicit || process.env.CHROME_PATH || process.env.PUPPETEER_EXECUTABLE_PATH;
  if (fromEnv) { try { await fs.access(fromEnv); return fromEnv; } catch { /* fall through */ } }
  for (const p of APP_CANDIDATES) { try { await fs.access(p); return p; } catch { /* next */ } }
  for (const name of PATH_CANDIDATES) { if (await onPath(name)) return name; }
  return null;
}

export async function screenshot(target, opts = {}) {
  const host = validateTarget(target);
  const url = buildUrl(opts.scheme || 'https', host, opts.path || '/');

  const browser = await findBrowser(opts.chromePath);
  if (!browser) {
    return {
      target: host, url, captured: false,
      note: 'Skipped — no headless browser found. Install Chrome/Chromium (or set CHROME_PATH) to enable screenshots.',
    };
  }

  const width = Math.min(Math.max(opts.width || 1280, 320), 3840);
  const height = Math.min(Math.max(opts.height || 800, 240), 2160);
  const outFile = opts.outFile || path.join(os.tmpdir(), `cats-shot-${host}-${Date.now()}.png`);

  const args = [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--hide-scrollbars',
    '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check',
    `--virtual-time-budget=${opts.waitMs || 4000}`,
    `--window-size=${width},${height}`,
    `--screenshot=${outFile}`,
    url,
  ];

  try {
    await pexecFile(browser, args, { timeout: opts.timeoutMs || 45000, maxBuffer: 4 * 1024 * 1024 });
  } catch (e) {
    // Chrome often exits non-zero even on a successful screenshot; verify the file.
    try { await fs.access(outFile); } catch {
      return { target: host, url, captured: false, browser, error: e.message };
    }
  }

  let bytes = 0;
  try { bytes = (await fs.stat(outFile)).size; } catch {
    return { target: host, url, captured: false, browser, error: 'screenshot file not produced' };
  }

  return {
    target: host, url, captured: bytes > 0,
    browser,
    file: outFile,
    bytes,
    dimensions: { width, height },
  };
}
