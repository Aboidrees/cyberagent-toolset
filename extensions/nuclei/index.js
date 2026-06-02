import { scan } from './src/nuclei.js';
import { findings } from './report.js';

/** Nuclei — thousands of community templates (CVEs, exposures, misconfigs). */
export default {
  name: 'nuclei',
  version: '1.0.0',
  domain: 'nuclei',
  description: 'Nuclei template scanning — thousands of community checks (CVEs, exposures, misconfigurations). Requires the nuclei binary.',
  permissions: { network: ['http', 'https'], env: [], bins: ['nuclei'] },
  report: { findings },
  executors: [
    {
      uses: 'nuclei.scan',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'url', 'ip'],
      summary: 'Run nuclei templates against the target (no-op if the binary is absent). Authorized targets only.',
      run: scan,
      inputSchema: {
        target: { type: 'string', description: 'Hostname or IP' },
        scheme: { type: 'string', description: '"http" or "https". Default: "https"' },
        severity: { type: 'string', description: 'Comma list: info|low|medium|high|critical. Default: critical,high,medium' },
        tags: { type: 'string', description: 'Template tags, e.g. "cves,exposures" (optional)' },
        templates: { type: 'array', items: { type: 'string' }, description: 'Specific template paths/ids (optional)' },
      },
    },
  ],
};
