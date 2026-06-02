/** Findings from a nuclei scan — one per matched template. */
export function findings(output) {
  const out = [];
  for (const r of output.data?.results || []) {
    out.push({
      severity: r.severity,
      message: `${r.id || 'nuclei'}: ${r.name || ''} @ ${r.matchedAt}`,
    });
  }
  return out;
}
