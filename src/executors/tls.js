import tls from 'tls';
import { validateTarget } from '../utils/validate.js';

/**
 * Inspect TLS certificate and cipher information for a target host.
 *
 * Note: rejectUnauthorized is intentionally false — this tool is meant to
 * inspect certificates even when they are invalid or self-signed.
 * The caller should evaluate cert validity from the returned dates/issuer.
 */
export async function inspectTLS(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const port = opts.port || 443;
  const timeoutMs = opts.timeoutMs || 12000;

  return new Promise((resolve, reject) => {
    let settled = false;

    const socket = tls.connect(
      {
        host: cleanTarget,
        port,
        servername: cleanTarget,
        rejectUnauthorized: false,
      },
      () => {
        if (settled) return;
        settled = true;

        const cert   = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();

        resolve({
          servername: cleanTarget,
          port,
          cipher,
          cert: {
            subject:        cert.subject,
            issuer:         cert.issuer,
            valid_from:     cert.valid_from,
            valid_to:       cert.valid_to,
            altNames:       cert.subjectaltname,
            fingerprint256: cert.fingerprint256,
          },
        });

        socket.end();
      }
    );

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error(`TLS connect timeout after ${timeoutMs}ms`));
    }, timeoutMs);

    socket.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });

    socket.on('close', () => clearTimeout(timer));
  });
}
