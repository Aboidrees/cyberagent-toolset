import { greynoiseIp } from './src/greynoise.js';

/** GreyNoise — internet-noise / malicious-IP classification (key-gated). */
export default {
  name: 'greynoise',
  version: '1.0.0',
  domain: 'greynoise',
  description: 'GreyNoise — classify an IP as benign / malicious / background-noise and flag RIOT business services. Key-gated (GREYNOISE_API_KEY).',
  permissions: { network: ['https', 'dns'], env: ['GREYNOISE_API_KEY'], bins: [] },
  executors: [
    {
      uses: 'greynoise.ip', phase: 'reconnaissance', posture: 'passive', targetTypes: ['ip', 'domain'],
      summary: 'GreyNoise IP classification (noise / RIOT / malicious). Requires GREYNOISE_API_KEY.',
      run: greynoiseIp,
      inputSchema: { target: { type: 'string', description: 'IP or hostname (A-resolved)' }, apiKey: { type: 'string', description: 'GreyNoise key (or GREYNOISE_API_KEY)' } },
    },
  ],
};
