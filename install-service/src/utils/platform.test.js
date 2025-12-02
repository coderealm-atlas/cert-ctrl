import { describe, it, expect } from 'vitest';
import {
  detectPlatform,
  detectArchitecture,
  normalizePlatformHint,
  normalizeArchitectureHint
} from './platform.js';

const freebsdUA = 'curl/8.5.0 (x86_64-pc-freebsd13.2) libcurl/8.5.0 OpenSSL/3.0.10 zlib/1.3';
const genericCurl = 'curl/8.6.0';
const libfetchUA = 'fetch libfetch/2.0';

describe('platform detection utilities', () => {
  it('identifies FreeBSD user agents and architecture', () => {
    const detection = detectPlatform(freebsdUA, 'bash');
    expect(detection.platform).toBe('freebsd');
    expect(detection.confidence).toBe('high');
    expect(detectArchitecture(freebsdUA)).toBe('x64');
  });

  it('falls back to low-confidence linux when UA lacks OS hints', () => {
    const detection = detectPlatform(genericCurl, 'bash');
    expect(detection.platform).toBe('linux');
    expect(detection.confidence).toBe('low');
  });

  it('treats libfetch requests as FreeBSD', () => {
    const detection = detectPlatform(libfetchUA, 'bash');
    expect(detection.platform).toBe('freebsd');
    expect(detection.confidence).toBe('high');
  });

  it('normalizes manual overrides', () => {
    expect(normalizePlatformHint('FreeBSD')).toBe('freebsd');
    expect(normalizePlatformHint('  macOS ')).toBe('macos');
    expect(normalizePlatformHint('windows')).toBe('windows');
    expect(normalizeArchitectureHint('AMD64')).toBe('x64');
    expect(normalizeArchitectureHint('aArch64')).toBe('arm64');
    expect(normalizeArchitectureHint('armv7')).toBe('arm');
  });
});
