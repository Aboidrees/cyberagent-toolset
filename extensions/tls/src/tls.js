import tls from 'tls';
import https from 'https';
import { validateTarget } from '#sdk';

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

// ─────────────────────────────────────────────────────────────────────────────
// tls.deep — vulnerability-oriented TLS analysis
// ─────────────────────────────────────────────────────────────────────────────

// Node's min/maxVersion knobs let us probe each protocol independently.
const PROTOCOLS = [
  { id: 'TLSv1',   label: 'TLS 1.0', deprecated: true },
  { id: 'TLSv1.1', label: 'TLS 1.1', deprecated: true },
  { id: 'TLSv1.2', label: 'TLS 1.2', deprecated: false },
  { id: 'TLSv1.3', label: 'TLS 1.3', deprecated: false },
];

// OpenSSL cipher strings that should no longer negotiate on a hardened server.
// @SECLEVEL=0 lets our local OpenSSL 3 even *offer* these legacy ciphers; a
// successful negotiation then means the remote server still accepts them.
const WEAK_CIPHER_PROBES = [
  { id: 'RC4',  ciphers: 'RC4-SHA:RC4-MD5:ECDHE-RSA-RC4-SHA:@SECLEVEL=0' },
  { id: '3DES', ciphers: 'DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:@SECLEVEL=0' },
  { id: 'NULL', ciphers: 'NULL-SHA:NULL-MD5:eNULL:@SECLEVEL=0' },
];

/**
 * Attempt a single TLS connection with explicit version/cipher constraints.
 * Resolves with connection metadata on success, or { ok:false } on any failure
 * (a failure to negotiate is the expected, desirable result for weak configs).
 */
function probe(host, port, options, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    let socket;
    let timer;
    const done = (val) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try { socket?.destroy(); } catch {}
      resolve(val);
    };

    // tls.connect can throw synchronously when the local OpenSSL rejects the
    // requested cipher/protocol config — treat that as "did not negotiate".
    try {
      socket = tls.connect(
        { host, port, servername: host, rejectUnauthorized: false, ...options },
        () => {
          done({
            ok: true,
            protocol: socket.getProtocol(),
            cipher: socket.getCipher(),
            authorized: socket.authorized,
            authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          });
        }
      );
      socket.on('error', () => done({ ok: false }));
    } catch {
      return done({ ok: false, unsupportedLocally: true });
    }

    timer = setTimeout(() => done({ ok: false, timedOut: true }), timeoutMs);
  });
}

/**
 * Check OCSP stapling by requesting a stapled response during the handshake.
 */
function checkOcspStapling(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let stapled = false;
    let settled = false;
    let timer;
    const done = (val) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try { socket.destroy(); } catch {}
      resolve(val);
    };

    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, requestOCSP: true },
      () => done({ stapled })
    );
    socket.on('OCSPResponse', (resp) => { stapled = Boolean(resp && resp.length); });
    socket.on('error', () => done({ stapled: false, error: true }));
    timer = setTimeout(() => done({ stapled: false, timedOut: true }), timeoutMs);
  });
}

/**
 * Fetch the HSTS header over HTTPS and report preload eligibility.
 */
function checkHsts(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const req = https.request(
      { host, port, method: 'HEAD', path: '/', servername: host, rejectUnauthorized: false, timeout: timeoutMs },
      (res) => {
        const header = res.headers['strict-transport-security'] || null;
        const maxAge = header ? Number((header.match(/max-age=(\d+)/i) || [])[1] || 0) : 0;
        res.resume();
        resolve({
          present: Boolean(header),
          header,
          maxAge,
          includeSubDomains: header ? /includeSubDomains/i.test(header) : false,
          preload: header ? /preload/i.test(header) : false,
          preloadEligible: Boolean(header) && maxAge >= 31536000 && /includeSubDomains/i.test(header) && /preload/i.test(header),
        });
      }
    );
    req.on('error', () => resolve({ present: false, error: true }));
    req.on('timeout', () => { req.destroy(); resolve({ present: false, timedOut: true }); });
    req.end();
  });
}

/**
 * Deep TLS analysis — extends tls.inspect with vulnerability-oriented checks:
 * supported protocol versions, weak-cipher negotiation, certificate chain
 * validation, OCSP stapling, and HSTS / preload status. Keyless.
 */
export async function deepTLS(target, opts = {}) {
  const cleanTarget = validateTarget(target);
  const port = opts.port || 443;
  const timeoutMs = opts.timeoutMs || 10000;
  const findings = [];

  // ── Protocol support matrix ────────────────────────────────────────────────
  const protocols = {};
  for (const p of PROTOCOLS) {
    // Deprecated protocols need a relaxed (SECLEVEL=0) cipher list so our local
    // OpenSSL will even attempt the legacy handshake — otherwise we'd report a
    // false "unsupported" for a server that genuinely still speaks TLS 1.0/1.1.
    const opts = { minVersion: p.id, maxVersion: p.id };
    if (p.deprecated) opts.ciphers = 'DEFAULT:@SECLEVEL=0';
    const r = await probe(cleanTarget, port, opts, timeoutMs);
    protocols[p.label] = r.ok;
    if (r.ok && p.deprecated) {
      findings.push({ severity: 'high', message: `${p.label} is supported but deprecated — disable it.` });
    }
  }
  if (!protocols['TLS 1.2'] && !protocols['TLS 1.3']) {
    findings.push({ severity: 'high', message: 'Neither TLS 1.2 nor 1.3 negotiated — modern clients may fail to connect.' });
  }

  // ── Weak cipher probes ─────────────────────────────────────────────────────
  const weakCiphers = [];
  for (const probeDef of WEAK_CIPHER_PROBES) {
    // Weak ciphers only exist under TLS 1.2 and below.
    const r = await probe(cleanTarget, port, { ciphers: probeDef.ciphers, maxVersion: 'TLSv1.2' }, timeoutMs);
    if (r.ok) {
      weakCiphers.push(probeDef.id);
      findings.push({ severity: 'high', message: `Weak cipher family negotiated: ${probeDef.id}.` });
    }
  }

  // ── Certificate chain validation ───────────────────────────────────────────
  const validated = await probe(cleanTarget, port, { ciphers: 'DEFAULT:@SECLEVEL=0' }, timeoutMs);
  const chain = {
    connected: validated.ok || false,
    authorized: validated.authorized || false,
    authorizationError: validated.authorizationError || null,
    negotiatedProtocol: validated.protocol || null,
    negotiatedCipher: validated.cipher?.name || null,
  };
  if (!validated.ok) {
    findings.push({ severity: 'medium', message: 'Could not complete a TLS handshake from this client (server may only offer legacy protocols/ciphers).' });
  } else if (!chain.authorized) {
    findings.push({ severity: 'medium', message: `Certificate chain did not validate: ${chain.authorizationError || 'untrusted or incomplete chain'}.` });
  }

  // ── OCSP stapling & HSTS ───────────────────────────────────────────────────
  const ocsp = await checkOcspStapling(cleanTarget, port, timeoutMs);
  if (!ocsp.stapled) {
    findings.push({ severity: 'low', message: 'No OCSP stapling — clients must contact the CA to check revocation.' });
  }

  const hsts = await checkHsts(cleanTarget, port, timeoutMs);
  if (!hsts.present) {
    findings.push({ severity: 'medium', message: 'No HSTS header — connections can be downgraded to HTTP.' });
  } else if (!hsts.preloadEligible) {
    findings.push({ severity: 'low', message: 'HSTS present but not preload-eligible (need max-age>=1y, includeSubDomains, preload).' });
  }

  return {
    target: cleanTarget,
    port,
    protocols,
    weakCiphers,
    chain,
    ocspStapling: ocsp.stapled,
    hsts,
    findings,
  };
}
