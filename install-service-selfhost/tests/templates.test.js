import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { getInstallTemplate, getUninstallTemplate } from '../src/utils/templates.js';

function baseOptions(overrides = {}) {
  return {
    platform: 'linux',
    platformConfidence: 'high',
    architecture: 'x64',
    country: 'US',
    mirror: { name: 'primary', url: 'https://example.invalid/releases/proxy' },
    params: {
      version: 'v0.0.0',
      verbose: false,
      force: false,
      installDir: '',
      dryRun: false,
      writableDirs: '',
      disableSandbox: false
    },
    baseUrl: 'https://install.example',
    ...overrides
  };
}

test('bash install template renders and preserves bash parameter expansion', async () => {
  const script = await getInstallTemplate('bash', baseOptions());

  assert.ok(script.includes('#!/bin/bash'));
  // This is a literal bash expansion; it must not be treated as JS ${...}.
  assert.ok(script.includes('if [ -n "${VERSION:-}" ]'));
});

test('bash installer dry-run accepts a nested install path without writing it', async () => {
  const script = await getInstallTemplate('bash', baseOptions());
  const workDir = mkdtempSync(join(tmpdir(), 'certctrl-selfhost-dry-run-'));
  const scriptPath = join(workDir, 'install.sh');
  writeFileSync(scriptPath, script, { mode: 0o755 });

  assert.doesNotThrow(() => execFileSync(
    'bash',
    [
      scriptPath,
      '--dry-run',
      '--no-service',
      '--install-dir',
      join(workDir, 'missing', 'bin')
    ],
    { env: { ...process.env, BASE_URL: '', MIRROR_URL: '', VERSION: '' } }
  ));
});

test('powershell install template includes CA bundle install hook', async () => {
  const options = baseOptions({ platform: 'windows' });
  options.params = { ...options.params, installDir: 'C:\\Tools\\cert-ctrl' };
  const script = await getInstallTemplate('powershell', options);

  assert.ok(script.includes('# cert-ctrl installation script (PowerShell)'));
  assert.ok(script.includes('$env:ProgramData'));
  assert.ok(script.toLowerCase().includes('cacert.pem'));
  assert.ok(script.includes('Get-FileHash -Path $zipPath -Algorithm SHA256'));
  assert.ok(script.includes('restoring the previous cert-ctrl binary'));
  assert.ok(script.includes('[string]$InstallDir = "C:\\Tools\\cert-ctrl"'));
  assert.ok(script.includes('[switch]$ReplaceService'));
  assert.ok(script.includes('-ReplaceService:$paramReplaceService'));
  assert.ok(!script.includes('-ForceInstall:$paramForceInstall'));
});

test('install template rejects command substitution in query-derived values', async () => {
  await assert.rejects(
    getInstallTemplate('bash', baseOptions({
      params: {
        ...baseOptions().params,
        installDir: '$(touch /tmp/certctrl-template-injection)'
      }
    })),
    /Invalid install-dir/
  );

  await assert.rejects(
    getInstallTemplate('bash', baseOptions({
      params: {
        ...baseOptions().params,
        version: 'latest$(id)'
      }
    })),
    /Invalid version/
  );
});

test('bash installer separates binary reinstall from config and service replacement', async () => {
  const script = await getInstallTemplate('bash', baseOptions());

  assert.ok(script.includes('REPLACE_CONFIG="${REPLACE_CONFIG:-false}"'));
  assert.ok(script.includes('REPLACE_SERVICE="${REPLACE_SERVICE:-false}"'));
  assert.ok(script.includes('refusing an unverified installation'));
  assert.ok(script.includes('rollback_failed_upgrade_on_exit'));
  assert.ok(script.includes('refusing to replace a running installation'));
  assert.ok(script.includes('Configuration or service replacement requested'));
  assert.ok(!script.includes('NONINTERACTIVE="true"\n            FORCE=true'));
});

test('bash uninstall template renders', async () => {
  const script = await getUninstallTemplate('bash', baseOptions());

  assert.ok(script.includes('# cert-ctrl uninstallation script'));
  assert.ok(script.includes('cert-ctrl uninstall'));
});
