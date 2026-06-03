/**
 * Target-aware auto-assembly.
 *
 * Infers a target's type, then selects the executors whose `targetTypes` apply
 * and assembles them into an in-memory playbook — "point it at a target and run
 * all applicable recon," with no hand-written playbook.
 */

const IPV4_RE      = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV4_CIDR_RE = /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/;

/** Classify a target as url | cidr | ip | domain. */
export function inferTargetType(target) {
  if (/^https?:\/\//i.test(target)) return 'url';
  if (IPV4_CIDR_RE.test(target)) return 'cidr';
  if (IPV4_RE.test(target) || (target.includes(':') && /^[0-9a-f:]+$/i.test(target))) return 'ip';
  return 'domain';
}

/** Reduce a target to the clean host value executors expect. */
export function targetHost(target, type = inferTargetType(target)) {
  if (type === 'url') {
    try { return new URL(target).hostname; } catch { return target; }
  }
  return target;
}

const PHASE_ORDER = { reconnaissance: 0, scanning: 1, 'gaining-access': 2 };

/**
 * Build an in-memory playbook of the executors applicable to a target.
 *
 * @param catalog              the loaded extension catalog
 * @param opts.target          the raw target (domain/ip/cidr/url)
 * @param opts.phase           'reconnaissance' (default) | 'scanning' | 'gaining-access' | 'all'
 * @param opts.posture         'passive' to include only passive executors
 * @param opts.includeKeyless  reserved
 */
export function assemble(catalog, { target, phase = 'reconnaissance', posture } = {}) {
  const type = inferTargetType(target);
  const host = targetHost(target, type);
  // A URL is a web target on a domain — match both.
  const wanted = type === 'url' ? ['url', 'domain'] : [type];

  let execs = catalog.executors.filter(e => (e.targetTypes || []).some(t => wanted.includes(t)));
  if (phase !== 'all') execs = execs.filter(e => e.phase === phase);
  if (posture === 'passive') execs = execs.filter(e => e.posture === 'passive');

  execs.sort((a, b) =>
    (PHASE_ORDER[a.phase] - PHASE_ORDER[b.phase]) ||
    a.domain.localeCompare(b.domain) ||
    a.uses.localeCompare(b.uses));

  const steps = execs.map(e => ({ name: e.summary || e.uses, uses: e.uses, with: {} }));

  return {
    id: 'auto',
    title: `Auto ${phase} ${host}`,
    description: `Auto-assembled ${phase} run (${steps.length} executors applicable to a ${type}).`,
    vars: { target: host },
    steps,
    // metadata for the CLI summary (ignored by the runner)
    _meta: { type, host, phase, selected: steps.length },
  };
}
