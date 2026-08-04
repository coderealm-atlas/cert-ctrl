import test from 'node:test';
import assert from 'node:assert/strict';

import { parseBooleanFlag, validateInstallTemplateOptions } from '../src/utils/install-params.js';

test('boolean query flags honor explicit false values', () => {
  assert.equal(parseBooleanFlag('false', true), false);
  assert.equal(parseBooleanFlag('0', true), false);
  assert.equal(parseBooleanFlag('true', true), true);
  assert.equal(parseBooleanFlag('', true), true);
  assert.equal(parseBooleanFlag('true', false), false);
});

test('template metadata rejects injected header and host values', () => {
  const options = {
    platform: 'linux',
    platformConfidence: 'high',
    architecture: 'x64',
    country: 'US\nmalicious-command',
    mirror: { name: 'primary', url: 'https://install.example/releases/proxy' },
    params: { version: 'latest', installDir: '' },
    baseUrl: 'https://install.example'
  };

  assert.throws(() => validateInstallTemplateOptions('bash', options), /Invalid country/);
  assert.throws(
    () => validateInstallTemplateOptions('bash', {
      ...options,
      country: 'US',
      baseUrl: 'https://example.invalid/$(id)'
    }),
    /Invalid base URL/
  );
});
