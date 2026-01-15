import test from 'node:test';
import assert from 'node:assert/strict';

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

test('powershell install template includes CA bundle install hook', async () => {
  const script = await getInstallTemplate('powershell', baseOptions({ platform: 'windows' }));

  assert.ok(script.includes('# cert-ctrl installation script (PowerShell)'));
  assert.ok(script.includes('$env:ProgramData'));
  assert.ok(script.toLowerCase().includes('cacert.pem'));
});

test('bash uninstall template renders', async () => {
  const script = await getUninstallTemplate('bash', baseOptions());

  assert.ok(script.includes('# cert-ctrl uninstallation script'));
  assert.ok(script.includes('cert-ctrl uninstall'));
});
