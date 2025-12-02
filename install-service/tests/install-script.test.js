import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { getInstallTemplate } from '../src/utils/templates.js';

const defaultOptions = {
  platform: 'linux',
  architecture: 'x64',
  country: 'US',
  mirror: {
    name: 'cloudflare-proxy',
    url: 'https://install.lets-script.com/releases/proxy'
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

describe('install.sh template', () => {
  it('renders bash script that passes a syntax check', async () => {
    const script = await getInstallTemplate('bash', defaultOptions);
    const workDir = mkdtempSync(join(tmpdir(), 'certctrl-install-'));
    const scriptPath = join(workDir, 'install.sh');
    writeFileSync(scriptPath, script, { mode: 0o755 });

    const runSyntaxCheck = () => execFileSync('bash', ['-n', scriptPath]);
    expect(runSyntaxCheck).not.toThrow();
  });

  it('includes jq-less awk fallback for version resolution', async () => {
    const script = await getInstallTemplate('bash', defaultOptions);
    const awkFallback = `awk -F'"' '/"version":/ {print $4; exit}'`;

    expect(script).toContain(awkFallback);
    expect(script).not.toContain('\\1');
  });

  it('logs a helpful warning if version extraction fails', async () => {
    const script = await getInstallTemplate('bash', defaultOptions);
    const warningText = 'Unable to parse version from $latest_url; install jq or inspect the API response';

    expect(script).toContain(warningText);
  });

  it('sources /etc/os-release safely to handle missing VERSION_ID', async () => {
    const script = await getInstallTemplate('bash', defaultOptions);

    expect(script).toContain('. /etc/os-release');
    expect(script).toContain('OS_VERSION_ID="${VERSION_ID:-${BUILD_ID:-}}"');
    expect(script).toContain('local requested_version="${VERSION-}"');
    expect(script).toContain('if [ -z "$OS_ID" ]; then');
  });

  it('guides users to warm up sudo credentials before running', async () => {
    const script = await getInstallTemplate('bash', defaultOptions);

    expect(script).toContain('sudo -v && curl -fsSL');
  });

  it('warns when service-provided platform differs from host detection', async () => {
    const script = await getInstallTemplate('bash', defaultOptions);

    expect(script).toContain('service suggested');
  });

  it('uses portable sed helper for FreeBSD rc.d templating', async () => {
    const script = await getInstallTemplate('bash', defaultOptions);

    expect(script).toContain('portable_sed_inplace');
    expect(script).toContain('portable_sed_inplace "s|@@BINARY_PATH@@|$INSTALL_DIR/cert-ctrl|g"');
    expect(script).toContain(': ${@@RC_NAME@@_enable:="NO"}');
  });

  it('wraps FreeBSD rc.d command with /usr/sbin/daemon', async () => {
    const script = await getInstallTemplate('bash', defaultOptions);

    expect(script).toContain('command="/usr/sbin/daemon"');
    expect(script).toContain('procname="@@BINARY_PATH@@"');
    expect(script).toContain('command_args="-p /var/run/${name}.pid @@BINARY_PATH@@ --config-dirs @@CONFIG_DIR@@ --keep-running"');
    expect(script).toContain(': ${@@RC_NAME@@_limits:=""}');
  });
});
