import { sshAudit } from './src/ssh.js';

/** SSH algorithm audit — banner + KEXINIT weak-algorithm analysis (no auth). */
export default {
  name: 'ssh',
  version: '1.0.0',
  domain: 'ssh',
  description: 'SSH audit — server banner plus offered key-exchange, host-key, cipher, and MAC algorithms, flagging weak/deprecated ones. Read-only handshake, no authentication.',
  permissions: { network: ['tcp'], env: [], bins: [] },
  executors: [
    {
      uses: 'ssh.audit',
      phase: 'scanning',
      posture: 'active',
      targetTypes: ['domain', 'ip'],
      summary: 'SSH banner + KEXINIT algorithm audit (weak cipher/KEX/MAC/host-key detection).',
      run: sshAudit,
      inputSchema: {
        target: { type: 'string', description: 'Hostname or IP' },
        port: { type: 'number', description: 'SSH port. Default: 22' },
        timeoutMs: { type: 'number', description: 'Handshake timeout ms. Default: 10000' },
      },
    },
  ],
};
