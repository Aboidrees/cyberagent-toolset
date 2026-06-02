/** Findings extraction owned by the cloud extension. */
export function findings(output) {
  const out = [];
  if (output.uses === 'cloud.bucket_finder') {
    for (const b of output.data?.exposed || []) {
      out.push({ severity: b.severity, message: `Public bucket: ${b.url} (${b.access})` });
    }
  }
  return out;
}
