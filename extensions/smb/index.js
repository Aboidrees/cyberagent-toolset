import { smbProbe } from './src/smb.js';

/** SMB negotiation probe — dialect + signing posture (read-only, no auth). */
export default {
  name: 'smb',
  version: '1.0.0',
  domain: 'smb',
  description: 'SMB negotiation probe — SMB2 NEGOTIATE over TCP/445 reporting the negotiated dialect and signing posture; flags signing-not-required (NTLM relay risk). No authentication.',
  permissions: { network: ['tcp'], env: [], bins: [] },
  executors: [
    {
      uses: 'smb.probe',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'SMB2 NEGOTIATE — dialect + signing-required check (flags NTLM-relay exposure).',
      run: smbProbe,
      inputSchema: {
        target: { type: 'string', description: 'Hostname or IP' },
        port: { type: 'number', description: 'SMB port. Default: 445' },
        timeoutMs: { type: 'number', description: 'Negotiate timeout ms. Default: 8000' },
      },
    },
  ],
};
