import net from 'net';
import dns from 'dns/promises';
import { validateTarget } from '#sdk';

/**
 * Active SMTP posture probe. Resolves the domain's MX, connects to the mail
 * server, reads the EHLO capability set, and reports on transport security:
 * STARTTLS support, advertised AUTH mechanisms, and whether plaintext auth is
 * offered before TLS. Read-only — it never sends a message. The optional
 * open-relay heuristic (opts.relayTest) issues MAIL FROM / RCPT TO and aborts
 * with RSET/QUIT *before* DATA, so nothing is ever delivered.
 */

const OUR_EHLO = 'recon-probe.invalid';

/** Send a command (or read banner if cmd is null) and collect the full reply. */
function smtpExchange(socket, cmd, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const onData = (d) => {
      buf += d.toString('utf8');
      // A complete reply ends with a line "NNN <text>" (space, not hyphen).
      const lines = buf.split(/\r?\n/).filter(Boolean);
      const last = lines[lines.length - 1] || '';
      if (/^\d{3} /.test(last)) { cleanup(); resolve(buf); }
    };
    const onErr = (e) => { cleanup(); reject(e); };
    const onTimeout = () => { cleanup(); reject(new Error('smtp timeout')); };
    const cleanup = () => {
      socket.removeListener('data', onData);
      socket.removeListener('error', onErr);
      clearTimeout(timer);
    };
    const timer = setTimeout(onTimeout, timeoutMs);
    socket.on('data', onData);
    socket.once('error', onErr);
    if (cmd) socket.write(cmd + '\r\n');
  });
}

function parseEhlo(reply) {
  const caps = [];
  for (const line of reply.split(/\r?\n/)) {
    const m = /^250[ -](.+)$/.exec(line.trim());
    if (m) caps.push(m[1].trim());
  }
  const find = (kw) => caps.find(c => c.toUpperCase().startsWith(kw));
  const authLine = find('AUTH');
  return {
    capabilities: caps,
    starttls: caps.some(c => /^STARTTLS$/i.test(c)),
    authMechanisms: authLine ? authLine.split(/\s+/).slice(1) : [],
    size: (find('SIZE') || '').split(/\s+/)[1] || null,
  };
}

export async function smtpProbe(target, opts = {}) {
  const domain = validateTarget(target);
  const port = opts.port || 25;
  const timeoutMs = opts.timeoutMs || 10000;

  // Resolve MX (fall back to the domain itself, A-record mail server).
  let mxHost = opts.mx;
  if (!mxHost) {
    try {
      const mx = await dns.resolveMx(domain);
      if (mx.length) mxHost = mx.sort((a, b) => a.priority - b.priority)[0].exchange;
    } catch { /* no MX */ }
  }
  mxHost = mxHost || domain;

  const result = { target: domain, mx: mxHost, port, reachable: false, findings: [] };
  let socket;
  try {
    socket = net.connect({ host: mxHost, port });
    socket.setTimeout(timeoutMs);
    await new Promise((res, rej) => {
      socket.once('connect', res);
      socket.once('error', rej);
      socket.once('timeout', () => rej(new Error('connect timeout')));
    });
    result.reachable = true;

    const banner = await smtpExchange(socket, null, timeoutMs);
    result.banner = (banner.split(/\r?\n/)[0] || '').trim();

    const ehlo = await smtpExchange(socket, `EHLO ${OUR_EHLO}`, timeoutMs);
    const parsed = parseEhlo(ehlo);
    Object.assign(result, parsed);

    // Transport-security findings.
    if (!parsed.starttls) {
      result.findings.push({ severity: 'medium', message: 'SMTP server does not advertise STARTTLS (cleartext transport)' });
    }
    if (parsed.authMechanisms.length && !parsed.starttls) {
      result.findings.push({ severity: 'high', message: `AUTH offered without STARTTLS (${parsed.authMechanisms.join(', ')}) — credentials in cleartext` });
    }

    // Optional, opt-in open-relay heuristic — aborts before DATA.
    if (opts.relayTest) {
      try {
        const from = await smtpExchange(socket, `MAIL FROM:<probe@${OUR_EHLO}>`, timeoutMs);
        if (/^2\d\d/.test(from.trim())) {
          const rcpt = await smtpExchange(socket, 'RCPT TO:<relay-test@example.org>', timeoutMs);
          const accepted = /^2\d\d/.test(rcpt.trim());
          result.openRelay = accepted;
          if (accepted) {
            result.findings.push({ severity: 'critical', message: 'Possible OPEN RELAY — accepted RCPT to an external domain without authentication' });
          }
          await smtpExchange(socket, 'RSET', timeoutMs).catch(() => {});
        }
      } catch { /* relay test inconclusive */ }
    }

    try { socket.write('QUIT\r\n'); } catch { /* ignore */ }
    return result;
  } catch (e) {
    result.error = e.code || e.message;
    return result;
  } finally {
    if (socket) socket.destroy();
  }
}
