import { Buffer } from 'node:buffer';
import { describe, it, expect, beforeEach, afterEach, afterAll, vi } from 'vitest';
import { __testables__ } from './proxy.js';

const { resolveDownloadSource } = __testables__;

class FakeKV {
  constructor() {
    this.store = new Map();
  }

  async get(key, type) {
    if (!this.store.has(key)) {
      return null;
    }
    const value = this.store.get(key);
    if (type === 'json') {
      if (typeof value === 'string') {
        return JSON.parse(value);
      }
      if (value instanceof ArrayBuffer) {
        return JSON.parse(Buffer.from(value).toString('utf-8'));
      }
    }
    if (type === 'arrayBuffer') {
      if (value instanceof ArrayBuffer) {
        return value;
      }
      if (typeof value === 'string') {
        return new TextEncoder().encode(value).buffer;
      }
    }
    return value;
  }

  async put(key, value) {
    this.store.set(key, value);
  }

  async delete(key) {
    this.store.delete(key);
  }
}

const realFetch = global.fetch;

describe('resolveDownloadSource', () => {
  let fetchMock;

  beforeEach(() => {
    fetchMock = vi.fn();
    global.fetch = fetchMock;
  });

  afterEach(() => {
    global.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it('returns asset URL from cached release metadata', async () => {
    const kv = new FakeKV();
    const assetUrl = 'https://install.lets-script.com/releases/proxy/v1.0.0/cert-ctrl-linux-x64.tar.gz';
    await kv.put('release_meta:v1.0.0', JSON.stringify({
      assets: [
        {
          name: 'cert-ctrl-linux-x64.tar.gz',
          browser_download_url: assetUrl
        }
      ]
    }));

    const env = {
      GITHUB_REPO_OWNER: 'coderealm-atlas',
      GITHUB_REPO_NAME: 'cert-ctrl',
      RELEASE_CACHE: kv
    };

    const result = await resolveDownloadSource(env, 'v1.0.0', 'cert-ctrl-linux-x64.tar.gz');

    expect(result).toEqual(
      expect.objectContaining({
        downloadUrl: assetUrl,
        source: 'metadata'
      })
    );
    expect(result.asset).toEqual(
      expect.objectContaining({
        name: 'cert-ctrl-linux-x64.tar.gz'
      })
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('falls back to direct HEAD request when metadata is missing', async () => {
    const kv = new FakeKV();
    const env = {
      GITHUB_REPO_OWNER: 'coderealm-atlas',
      GITHUB_REPO_NAME: 'cert-ctrl',
      RELEASE_CACHE: kv
    };

    fetchMock
      .mockResolvedValueOnce({
        ok: false,
        status: 404,
        text: async () => 'not found'
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200
      });

    const result = await resolveDownloadSource(env, 'v1.0.1', 'cert-ctrl-linux-x64.tar.gz');

    const expectedUrl = 'https://github.com/coderealm-atlas/cert-ctrl/releases/download/v1.0.1/cert-ctrl-linux-x64.tar.gz';

    expect(result).toEqual(
      expect.objectContaining({
        downloadUrl: expectedUrl,
        source: 'direct-head'
      })
    );
    expect(result.asset).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'HEAD' }));
  });
});
