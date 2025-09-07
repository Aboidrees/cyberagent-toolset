import tls from 'tls';

// Inspect TLS certificate and cipher information for a target.
export async function inspectTLS(target, opts = {}) {
  const port = opts.port || 443;
  return await new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: target,
      port,
      servername: target,
      rejectUnauthorized: false
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const cipher = socket.getCipher();
      resolve({
        servername: target,
        port,
        cipher,
        cert: {
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          altNames: cert.subjectaltname,
          fingerprint256: cert.fingerprint256
        }
      });
      socket.end();
    });
    socket.setTimeout(12000, () => {
      socket.destroy();
      reject(new Error('TLS connect timeout'));
    });
    socket.on('error', reject);
  });
}