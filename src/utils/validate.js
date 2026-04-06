/**
 * Input validation utilities for recon targets.
 * Prevents command injection by enforcing strict allow-lists before
 * any target value is passed to a shell executor.
 */

// RFC-1123 hostname (with optional port stripped below)
const HOSTNAME_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

// Plain label (e.g. "localhost", "myserver") — no dots, no TLD required
const PLAIN_LABEL_RE = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?$/;

// IPv4 with optional CIDR suffix
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/\d{1,2})?$/;

// IPv6 — simplified, just checks valid hex/colon structure
const IPV6_RE = /^[0-9a-fA-F:]{2,39}$/;

// Characters that must never appear in a target (shell metacharacters)
const FORBIDDEN_RE = /[;&|`$<>()\[\]{}\\'"!#\n\r\t]/;

/**
 * Validate and return a sanitized target string.
 * Accepts: valid hostname, IPv4, IPv4 CIDR, IPv6, or plain label.
 * Throws an Error with a descriptive message on any invalid input.
 *
 * @param {string} target
 * @returns {string} trimmed, validated target
 */
export function validateTarget(target) {
  if (!target || typeof target !== 'string') {
    throw new Error('Target must be a non-empty string');
  }

  const t = target.trim();

  if (t.length === 0) {
    throw new Error('Target cannot be empty');
  }

  if (t.length > 253) {
    throw new Error(`Target is too long (${t.length} chars, max 253)`);
  }

  // Hard block on any shell metacharacter
  if (FORBIDDEN_RE.test(t)) {
    throw new Error(
      `Invalid target "${t}": contains forbidden characters. ` +
      `Only hostnames, IPv4/IPv6 addresses, and CIDR ranges are allowed.`
    );
  }

  // IPv4 (with optional CIDR)
  if (IPV4_RE.test(t)) {
    const parts = t.split('/')[0].split('.');
    const valid = parts.every(p => {
      const n = parseInt(p, 10);
      return n >= 0 && n <= 255;
    });
    if (!valid) {
      throw new Error(`Invalid IPv4 address: "${t}"`);
    }
    const cidr = t.includes('/') ? parseInt(t.split('/')[1], 10) : null;
    if (cidr !== null && (cidr < 0 || cidr > 32)) {
      throw new Error(`Invalid CIDR prefix length: "${t}"`);
    }
    return t;
  }

  // IPv6
  if (IPV6_RE.test(t)) {
    return t;
  }

  // FQDN hostname
  if (HOSTNAME_RE.test(t)) {
    return t;
  }

  // Plain single-label (e.g. "localhost")
  if (PLAIN_LABEL_RE.test(t)) {
    return t;
  }

  throw new Error(
    `Invalid target "${t}". ` +
    `Must be a valid hostname (e.g. example.com), IPv4 address, ` +
    `IPv4 CIDR range (e.g. 192.168.1.0/24), or IPv6 address.`
  );
}

/**
 * Validate nmap-style flag strings.
 * Only allows alphanumeric characters, hyphens, spaces, dots, slashes,
 * commas, and colons (sufficient for any legitimate nmap flags).
 *
 * @param {string} flags
 * @returns {string} validated flags string
 */
export function validateNmapFlags(flags) {
  if (typeof flags !== 'string') {
    throw new Error('nmap flags must be a string');
  }
  // Allow: letters, digits, hyphens, spaces, dots, slashes, commas, colons, equals
  if (!/^[a-zA-Z0-9 \-.,/:=_]+$/.test(flags)) {
    throw new Error(
      `Invalid nmap flags "${flags}": contains forbidden characters. ` +
      `Only alphanumeric, hyphens, spaces, dots, slashes, commas, colons are allowed.`
    );
  }
  return flags;
}
