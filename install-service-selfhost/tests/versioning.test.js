import test from 'node:test';
import assert from 'node:assert/strict';

import { classifyUpdateUrgency, compareVersions } from '../src/utils/versioning.js';

test('git-describe versions are ordered by commit distance', () => {
  assert.equal(compareVersions('v0.1.2-58-g242140ed', 'v0.1.2-48-g21b7a0d7'), 1);
  assert.equal(compareVersions('v0.1.2-48-g21b7a0d7', 'v0.1.2-58-g242140ed'), -1);
  assert.equal(compareVersions('v0.1.2-1-gabcdef01', 'v0.1.2'), 1);
  assert.equal(compareVersions('v1.2', 'v1.2.0'), 0);
});

test('unsupported versions are high urgency and normal upgrades are medium', () => {
  assert.equal(classifyUpdateUrgency({
    currentVersion: 'v0.1.0',
    latestVersion: 'v0.2.0',
    minimumSupportedVersion: 'v0.1.5'
  }), 'high');
  assert.equal(classifyUpdateUrgency({
    currentVersion: 'v0.1.2-48-g21b7a0d7',
    latestVersion: 'v0.1.2-58-g242140ed',
    minimumSupportedVersion: 'v0.0.1'
  }), 'medium');
});
