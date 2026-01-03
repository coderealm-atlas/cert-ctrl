import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { getUninstallTemplate } from '../src/utils/templates.js';

const defaultOptions = {
  platform: 'linux',
  architecture: 'x64',
  country: 'US',
  mirror: {
    name: 'n/a',
    url: ''
  },
  params: {
    version: 'latest',
    verbose: false,
    force: false,
    installDir: '',
    dryRun: false
  },
  baseUrl: 'https://install.lets-script.com'
};

describe('uninstall.sh template', () => {
  it('renders bash script that passes a syntax check', async () => {
    const script = await getUninstallTemplate('bash', defaultOptions);
    const workDir = mkdtempSync(join(tmpdir(), 'certctrl-uninstall-'));
    const scriptPath = join(workDir, 'uninstall.sh');
    writeFileSync(scriptPath, script, { mode: 0o755 });

    const runSyntaxCheck = () => execFileSync('bash', ['-n', scriptPath]);
    expect(runSyntaxCheck).not.toThrow();
  });
});
