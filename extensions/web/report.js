/**
 * Findings extraction owned by the web extension.
 * (http.cors_check / http.methods return generic `data.findings[]`, handled by
 * the core aggregator — only the bespoke shapes are extracted here.)
 */
export function findings(output) {
  const out = [];
  const d = output.data || {};

  if (output.uses === 'http.security_score') {
    if (['D', 'E', 'F'].includes(d.grade)) {
      out.push({
        severity: d.grade === 'F' ? 'high' : 'medium',
        message: `Security header grade ${d.grade} (${d.score}%)`,
      });
    }
    for (const leak of d.infoLeaks || []) out.push({ severity: 'low', message: leak });
  }

  if (output.uses === 'http.git_leak' && d.exposed) {
    out.push({ severity: 'critical', message: d.note || 'Exposed .git directory' });
  }

  return out;
}
