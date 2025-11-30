import { describe, it, expect } from 'vitest';
import { __testables__ } from './version.js';

const { extractDownloadUrls } = __testables__;

describe('extractDownloadUrls', () => {
  it('captures canonical linux, openssl3, and musl artifacts', () => {
    const urls = extractDownloadUrls([
      { name: 'cert-ctrl-linux-musl-x64.tar.gz', browser_download_url: 'https://example.com/linux-musl-x64' },
      { name: 'cert-ctrl-linux-x64-openssl3.tar.gz', browser_download_url: 'https://example.com/linux-x64-openssl3' },
      { name: 'cert-ctrl-linux-x64.tar.gz', browser_download_url: 'https://example.com/linux-x64' },
      { name: 'cert-ctrl-linux-x64.tar.gz.sha256', browser_download_url: 'https://example.com/checksum' }
    ]);

    expect(urls['linux-musl-x64']).toBe('https://example.com/linux-musl-x64');
    expect(urls['linux-x64-openssl3']).toBe('https://example.com/linux-x64-openssl3');
    expect(urls['linux-x64']).toBe('https://example.com/linux-x64');
  });

  it('detects other platforms without interference', () => {
    const urls = extractDownloadUrls([
      { name: 'cert-ctrl-linux-arm64.tar.gz', browser_download_url: 'https://example.com/linux-arm64' },
      { name: 'cert-ctrl-windows-x64.zip', browser_download_url: 'https://example.com/windows-x64' },
      { name: 'cert-ctrl-macos-arm64.tar.gz', browser_download_url: 'https://example.com/macos-arm64' },
      { name: 'cert-ctrl-macos-x64.tar.gz', browser_download_url: 'https://example.com/macos-x64' }
    ]);

    expect(urls['linux-arm64']).toBe('https://example.com/linux-arm64');
    expect(urls['windows-x64']).toBe('https://example.com/windows-x64');
    expect(urls['macos-arm64']).toBe('https://example.com/macos-arm64');
    expect(urls['macos-x64']).toBe('https://example.com/macos-x64');
  });
});
