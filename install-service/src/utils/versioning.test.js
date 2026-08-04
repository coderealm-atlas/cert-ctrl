import { describe, expect, it } from 'vitest';

import { classifyUpdateUrgency, compareVersions } from './versioning.js';

describe('versioning', () => {
  it('orders git-describe builds by commit distance', () => {
    expect(compareVersions('v0.1.2-58-g242140ed', 'v0.1.2-48-g21b7a0d7')).toBe(1);
    expect(compareVersions('v0.1.2-1-gabcdef01', 'v0.1.2')).toBe(1);
    expect(compareVersions('v1.2', 'v1.2.0')).toBe(0);
  });

  it('uses high urgency only when the current version is unsupported', () => {
    expect(classifyUpdateUrgency({
      currentVersion: 'v0.1.0',
      latestVersion: 'v0.2.0',
      minimumSupportedVersion: 'v0.1.5'
    })).toBe('high');
    expect(classifyUpdateUrgency({
      currentVersion: 'v0.1.2-48-g21b7a0d7',
      latestVersion: 'v0.1.2-58-g242140ed',
      minimumSupportedVersion: 'v0.0.1'
    })).toBe('medium');
  });
});
