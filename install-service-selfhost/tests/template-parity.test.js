import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const sharedFiles = [
  'templates/bash/sections.js',
  'templates/install-macos.sh.js',
  'templates/install.ps1.js',
  'src/utils/install-params.js',
  'src/utils/templates.js',
  'src/utils/versioning.js'
];

test('worker and self-hosted installer implementations share identical core files', async () => {
  for (const relativePath of sharedFiles) {
    const selfHosted = await readFile(new URL(`../${relativePath}`, import.meta.url), 'utf8');
    const worker = await readFile(new URL(`../../install-service/${relativePath}`, import.meta.url), 'utf8');
    assert.equal(worker, selfHosted, `${relativePath} drifted between installer services`);
  }
});
