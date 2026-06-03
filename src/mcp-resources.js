/**
 * MCP Resources — readable state the agent can fetch and cite without a tool call.
 *
 * Exposes the live capability catalog and every saved assessment (session JSON +
 * synthesized report) as MCP resources. An agent can read `cats://capabilities`
 * to learn what the toolset can do, or `cats://assessment/<id>/report` to ground
 * a summary in the actual findings — pull, not push.
 */

import { listAssessments, loadAssessment } from './assessment.js';
import { synthesize } from './assessment-report.js';

const CAPABILITIES_URI = 'cats://capabilities';
const ASSESSMENTS_URI = 'cats://assessments';

/** Build the capability snapshot (mirrors the cats_capabilities tool). */
function capabilitiesDoc(catalog) {
  return {
    executors: catalog.executors.length,
    extensions: catalog.descriptors.length,
    byPhase: Object.fromEntries(Object.entries(catalog.byPhase).map(([p, list]) =>
      [p, list.map(e => ({ uses: e.uses, posture: e.posture, domain: e.domain, summary: e.summary }))])),
    domains: Object.keys(catalog.byDomain).sort(),
  };
}

/** Static + dynamic resource list. */
export async function listResources(catalog) {
  const resources = [
    { uri: CAPABILITIES_URI, name: 'Capabilities', mimeType: 'application/json', description: 'Every executor by phase / posture / domain.' },
    { uri: ASSESSMENTS_URI, name: 'Assessments index', mimeType: 'application/json', description: 'All saved assessments (id, target, status, counts).' },
  ];
  for (const a of await listAssessments()) {
    resources.push({
      uri: `cats://assessment/${a.id}/report`,
      name: `Report — ${a.target} (${a.id})`,
      mimeType: 'text/markdown',
      description: `Prioritized report: ${a.steps} steps · ${a.findings} findings.`,
    });
  }
  return resources;
}

/** Templates for the parameterized resources. */
export function listResourceTemplates() {
  return [
    { uriTemplate: 'cats://assessment/{id}', name: 'Assessment session', mimeType: 'application/json', description: 'Raw assessment session (entities, findings, steps).' },
    { uriTemplate: 'cats://assessment/{id}/report', name: 'Assessment report', mimeType: 'text/markdown', description: 'Synthesized prioritized report.' },
  ];
}

const textContent = (uri, mimeType, text) => ({ contents: [{ uri, mimeType, text }] });

/** Resolve a resource URI to its contents. */
export async function readResource(uri, { catalog }) {
  if (uri === CAPABILITIES_URI) {
    return textContent(uri, 'application/json', JSON.stringify(capabilitiesDoc(catalog), null, 2));
  }
  if (uri === ASSESSMENTS_URI) {
    return textContent(uri, 'application/json', JSON.stringify(await listAssessments(), null, 2));
  }

  const m = /^cats:\/\/assessment\/([^/]+)(\/report)?$/.exec(uri);
  if (m) {
    const session = await loadAssessment(m[1]);
    if (!session) throw new Error(`Assessment "${m[1]}" not found.`);
    if (m[2]) {
      const { markdown } = synthesize(session);
      return textContent(uri, 'text/markdown', markdown);
    }
    return textContent(uri, 'application/json', JSON.stringify(session, null, 2));
  }

  throw new Error(`Unknown resource URI: "${uri}"`);
}
