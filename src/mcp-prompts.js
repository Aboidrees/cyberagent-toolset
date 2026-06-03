/**
 * MCP Prompts — one-click agent workflows.
 *
 * Prompts are pre-authored instruction templates an MCP client can surface to the
 * user ("/assess-domain"). They turn the multi-step assessment loop into a single
 * invocation: the prompt tells the agent exactly which `cats_assess_*` tools to
 * call and in what order, so a non-expert gets a full, well-driven assessment.
 */

const AUTH_NOTE = 'Only assess targets you own or are explicitly authorized to test.';

export const PROMPTS = [
  {
    name: 'assess-domain',
    description: 'Run a complete authorized recon assessment of a target, pivoting on what is found.',
    arguments: [
      { name: 'target', description: 'Domain, IP, or URL to assess', required: true },
      { name: 'passive', description: 'Set "true" for passive-only (no packets to the host)', required: false },
    ],
  },
  {
    name: 'triage-findings',
    description: 'Triage and prioritize the findings of an existing assessment into a remediation plan.',
    arguments: [
      { name: 'assessmentId', description: 'Assessment id from cats_assess_start', required: true },
    ],
  },
  {
    name: 'passive-osint',
    description: 'Passive-only OSINT footprint of a target — nothing touches the host.',
    arguments: [
      { name: 'target', description: 'Domain or IP', required: true },
    ],
  },
  {
    name: 'quick-recon',
    description: 'Fast essentials — DNS, TLS, headers, subdomains.',
    arguments: [
      { name: 'target', description: 'Domain or URL', required: true },
    ],
  },
];

const userMsg = (text) => ({ role: 'user', content: { type: 'text', text } });

/** Build the messages for a prompt name + arguments. Returns { description, messages }. */
export function getPrompt(name, args = {}) {
  const target = args.target || '<target>';
  const passive = String(args.passive).toLowerCase() === 'true';

  switch (name) {
    case 'assess-domain':
      return {
        description: `Authorized recon assessment of ${target}`,
        messages: [userMsg(
          `Conduct an authorized reconnaissance assessment of "${target}".\n\n` +
          `1. Call cats_assess_start with target="${target}"${passive ? ' and passive=true' : ''}.\n` +
          `2. Call cats_assess_run on the assessmentId (top 5) to execute the highest-priority actions.\n` +
          `3. As new entities surface (subdomains, IPs, open ports, CVEs), keep calling cats_assess_run ` +
          `to pivot on them — repeat until cats_assess_next returns nothing high-value.\n` +
          `4. Call cats_assess_report and present the result: top risks first (highest severity, then ` +
          `highest EPSS exploit-probability), the entity inventory, and concrete remediation advice.\n\n` +
          `${AUTH_NOTE}`
        )],
      };

    case 'triage-findings':
      return {
        description: `Triage findings for assessment ${args.assessmentId || '<id>'}`,
        messages: [userMsg(
          `Triage the findings for assessment "${args.assessmentId || '<id>'}".\n\n` +
          `1. Call cats_assess_report with that assessmentId.\n` +
          `2. Group findings by severity. For each high/critical item, explain the real-world risk ` +
          `(use the EPSS exploit-probability where present — high EPSS means likely to be exploited soon).\n` +
          `3. Produce a prioritized remediation plan, flagging anything that needs immediate attention.`
        )],
      };

    case 'passive-osint':
      return {
        description: `Passive OSINT footprint of ${target}`,
        messages: [userMsg(
          `Perform passive-only OSINT on "${target}" — no packets may reach the host.\n\n` +
          `1. Call cats_assess_start with target="${target}" and passive=true.\n` +
          `2. Call cats_assess_run repeatedly (top 5) until cats_assess_next is exhausted.\n` +
          `3. Call cats_assess_report and summarize the externally-visible footprint: subdomains, ` +
          `infrastructure/ASN, email-auth posture, and anything exposed in third-party data.\n\n` +
          `${AUTH_NOTE}`
        )],
      };

    case 'quick-recon':
      return {
        description: `Quick recon of ${target}`,
        messages: [userMsg(
          `Run a quick recon of "${target}". Call cats_play__quick_web_recon with target="${target}" ` +
          `(or cats_assess_start then cats_assess_run top 5), then summarize DNS, TLS, security headers, ` +
          `and discovered subdomains. ${AUTH_NOTE}`
        )],
      };

    default:
      throw new Error(`Unknown prompt: "${name}"`);
  }
}
