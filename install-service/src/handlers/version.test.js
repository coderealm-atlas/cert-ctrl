import { describe, it, expect, vi, afterEach } from 'vitest';
import { __testables__, versionHandler } from './version.js';

const { buildInstallCommands, extractDownloadUrls } = __testables__;

describe('version check upstream failures', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns a readable GitHub authentication error response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ message: 'Bad credentials' }), { status: 401 }
    )));
    const response = await versionHandler(new Request(
      'https://install.never-lost.app/api/version/check?current=v0.1.2'
    ), {
      RELEASE_CACHE: { get: vi.fn().mockResolvedValue(null) },
      GITHUB_REPO_OWNER: 'example',
      GITHUB_REPO_NAME: 'cert-ctrl',
      GITHUB_TOKEN: 'invalid-test-token'
    });

    expect(response.status).toBe(500);
    expect(response.bodyUsed).toBe(false);
    expect(await response.json()).toMatchObject({
      error: 'Failed to fetch latest version',
      details: { status: 401, reason: 'unauthorized', message: 'Bad credentials' }
    });
  });
});

describe('buildInstallCommands', () => {
  it('uses normal upgrade commands without forcing a reinstall', () => {
    const commands = buildInstallCommands();

    expect(commands.linux).not.toContain('force=1');
    expect(commands.macos).not.toContain('force=1');
    expect(commands.windows).not.toContain('force=1');
    expect(commands.linux).toContain('| sudo bash');
  });
});

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
