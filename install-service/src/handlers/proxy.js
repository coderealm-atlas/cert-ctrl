import { corsHeaders } from '../utils/cors.js';
import { buildGithubHeaders, describeGithubFailure } from '../utils/github.js';

export async function proxyHandler(request, env) {
  try {
    const url = new URL(request.url);
    const pathParts = url.pathname.split('/').filter(Boolean);

    // Extract version and filename from URL
    // Format: /releases/proxy/{version}/{filename}
    const version = pathParts[2];
    const rawFilename = pathParts.slice(3).join('/');
    const filename = rawFilename ? decodeURIComponent(rawFilename) : undefined;

    console.log('Proxy request received', {
      url: request.url,
      version,
      rawFilename,
      filename
    });

    console.log('GitHub token presence', {
      hasToken: Boolean(env.GITHUB_TOKEN)
    });
    
    if (!version || !filename) {
      return new Response('Invalid proxy URL format', {
        status: 400,
        headers: corsHeaders
      });
    }

    // Handle "latest" version
    let actualVersion = version;
    if (version === 'latest') {
      actualVersion = await getLatestVersion(env);
      if (!actualVersion) {
        return new Response('Could not resolve latest version', {
          status: 500,
          headers: corsHeaders
        });
      }
    }

    // Resolve the actual GitHub download URL, falling back to API lookups when needed
    const resolution = await resolveDownloadSource(env, actualVersion, filename);
    console.log('Resolution result', {
      requestedVersion: version,
      actualVersion,
      filename,
      resolution
    });
    if (!resolution?.downloadUrl) {
      return new Response(JSON.stringify({
        error: `Release file not found: ${filename}`,
        details: resolution?.details || 'Asset missing from GitHub release'
      }, null, 2), {
        status: 404,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }

    const githubUrl = resolution.downloadUrl;

    // Fetch from GitHub
    // For HEAD requests return header metadata without downloading the full asset
    if (request.method === 'HEAD') {
      console.log('Handling HEAD request', {
        version: actualVersion,
        filename,
        source: resolution?.source,
        hasAssetMeta: Boolean(resolution?.asset)
      });
      const responseHeaders = new Headers(corsHeaders);
      const assetMeta = resolution?.asset;

      if (assetMeta) {
        console.log('Using metadata for HEAD response', {
          version: actualVersion,
          filename,
          size: assetMeta.size,
          contentType: assetMeta.content_type
        });
        if (assetMeta.content_type) {
          responseHeaders.set('Content-Type', assetMeta.content_type);
        } else {
          responseHeaders.set('Content-Type', getContentType(filename));
        }
        if (typeof assetMeta.size === 'number') {
          responseHeaders.set('Content-Length', assetMeta.size.toString());
        }
        if (assetMeta.updated_at) {
          responseHeaders.set('Last-Modified', new Date(assetMeta.updated_at).toUTCString());
        }
      } else {
        const headResponse = await fetch(githubUrl, {
          method: 'HEAD',
          headers: buildGithubHeaders(env)
        });

        console.log('GitHub HEAD response', {
          url: githubUrl,
          status: headResponse.status,
          ok: headResponse.ok
        });

        if (!headResponse.ok) {
          const bodyText = await headResponse.text();
          const details = describeGithubFailure(headResponse, bodyText, env);
          return new Response(JSON.stringify({
            error: `HEAD failed for ${filename}`,
            details
          }, null, 2), {
            status: headResponse.status,
            headers: {
              'Content-Type': 'application/json',
              ...corsHeaders
            }
          });
        }

        headResponse.headers.forEach((value, key) => {
          responseHeaders.set(key, value);
        });
      }

      responseHeaders.set('X-Cache', 'MISS');
      responseHeaders.set('X-Version', actualVersion);
      if (resolution?.source) {
        responseHeaders.set('X-Source', resolution.source);
      }

      return new Response(null, {
        status: 200,
        headers: responseHeaders
      });
    }

    // Cache key must change when GitHub assets are replaced.
    // `gh release upload --clobber` keeps the tag name stable but changes the
    // underlying asset id/updated_at; without this, we can serve stale bytes for
    // the full TTL.
    const cacheKeyParts = [`release`, actualVersion, filename];
    const hasAssetIdentity = Boolean(resolution?.asset?.id || resolution?.asset?.updated_at);
    if (resolution?.asset?.id) {
      cacheKeyParts.push(`id=${resolution.asset.id}`);
    }
    if (resolution?.asset?.updated_at) {
      cacheKeyParts.push(`u=${resolution.asset.updated_at}`);
    }
    const cacheKey = cacheKeyParts.join(':');

    // Only use KV cache when we have a stable asset identity.
    // If metadata lookup fails and we fall back to direct URL probing, caching by
    // version+filename is unsafe when assets are clobbered in-place.
    if (hasAssetIdentity) {
      const cachedResponse = await env.RELEASE_CACHE.get(cacheKey, 'arrayBuffer');
      if (cachedResponse) {
        return new Response(cachedResponse, {
          headers: {
            'Content-Type': getContentType(filename),
            'Cache-Control': 'public, max-age=86400', // 24 hours
            'X-Cache': 'HIT',
            'X-Version': actualVersion,
            ...(resolution?.source ? { 'X-Source': resolution.source } : {}),
            ...corsHeaders
          }
        });
      }
    }

    const githubResponse = await fetch(githubUrl, {
      headers: buildGithubHeaders(env)
    });

    console.log('GitHub fetch response', {
      url: githubUrl,
      status: githubResponse.status,
      ok: githubResponse.ok
    });

    if (!githubResponse.ok) {
      const bodyText = await githubResponse.text();
      const details = describeGithubFailure(githubResponse, bodyText, env);
      console.error('GitHub proxy asset error:', {
        url: githubUrl,
        details
      });
      return new Response(JSON.stringify({
        error: `Release file not found: ${filename}`,
        details
      }, null, 2), {
        status: githubResponse.status,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }

    const content = await githubResponse.arrayBuffer();
    const contentType = githubResponse.headers.get('Content-Type') || getContentType(filename);

    // Cache the response (for smaller files only, e.g., < 10MB)
    if (hasAssetIdentity && content.byteLength < 10 * 1024 * 1024) {
      await env.RELEASE_CACHE.put(cacheKey, content, {
        expirationTtl: 86400 // 24 hours
      });
    }

    // Add download analytics
    if (env.ANALYTICS_ENABLED) {
      // Don't await this to avoid slowing down the download
      recordDownload(request, env, actualVersion, filename, content.byteLength);
    }

    return new Response(content, {
      headers: {
        'Content-Type': contentType,
        'Content-Length': content.byteLength.toString(),
        'Cache-Control': 'public, max-age=86400', // 24 hours
        'X-Cache': hasAssetIdentity ? 'MISS' : 'BYPASS',
        'X-Version': actualVersion,
        'X-Content-Length': content.byteLength.toString(),
        ...(resolution?.source ? { 'X-Source': resolution.source } : {}),
        ...corsHeaders
      }
    });

  } catch (error) {
    console.error('Proxy handler error:', error);
    
    return new Response('Proxy error', {
      status: 500,
      headers: {
        'Content-Type': 'text/plain',
        ...corsHeaders
      }
    });
  }
}

async function getLatestVersion(env) {
  try {
    const cacheKey = 'latest_release';
    let releaseData = await env.RELEASE_CACHE.get(cacheKey, 'json');

    if (!releaseData) {
      const apiUrl = `https://api.github.com/repos/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/releases/latest`;
      const headers = buildGithubHeaders(env, {
        Accept: 'application/vnd.github.v3+json'
      });

      const response = await fetch(apiUrl, { headers });

      if (response.ok) {
        releaseData = await response.json();
        await env.RELEASE_CACHE.put(cacheKey, JSON.stringify(releaseData), {
          expirationTtl: 600 // 10 minutes
        });
      } else {
        const bodyText = await response.text();
        const details = describeGithubFailure(response, bodyText, env);
        console.error('GitHub latest version lookup failed in proxy handler:', details);
      }
    }

    return releaseData?.tag_name;
  } catch (error) {
    console.error('Error getting latest version:', error);
    return null;
  }
}

async function resolveDownloadSource(env, version, filename) {
  const owner = env.GITHUB_REPO_OWNER;
  const repo = env.GITHUB_REPO_NAME;
  const directUrl = `https://github.com/${owner}/${repo}/releases/download/${version}/${encodeURIComponent(filename)}`;

  console.log('Resolving download source', {
    version,
    filename,
    directUrl
  });

  // Attempt metadata-assisted lookup first to reduce failed GETs.
  const metadata = await getReleaseMetadata(env, version);
  console.log('Metadata lookup result', {
    version,
    hasMetadata: Boolean(metadata),
    assetCount: metadata?.assets?.length || 0
  });
  const assetFromMeta = metadata?.assets?.find(asset => asset?.name === filename);
  if (assetFromMeta?.browser_download_url) {
    console.log('Found asset in metadata', {
      version,
      filename,
      source: 'metadata'
    });
    return {
      downloadUrl: assetFromMeta.browser_download_url,
      source: 'metadata',
      asset: assetFromMeta
    };
  }

  // Try direct URL if metadata missing or asset not listed.
  const directTest = await fetch(directUrl, {
    method: 'HEAD',
    headers: buildGithubHeaders(env)
  });

  console.log('Direct HEAD check', {
    url: directUrl,
    status: directTest.status,
    ok: directTest.ok
  });

  if (directTest.ok || directTest.status === 302) {
    return {
      downloadUrl: directUrl,
      source: 'direct-head'
    };
  }

  // When direct HEAD fails, refresh metadata from GitHub API in case cache was stale
  const refreshedMetadata = await getReleaseMetadata(env, version, { forceRefresh: true });
  console.log('Metadata refresh result', {
    version,
    hasMetadata: Boolean(refreshedMetadata),
    assetCount: refreshedMetadata?.assets?.length || 0
  });
  const refreshedAsset = refreshedMetadata?.assets?.find(asset => asset?.name === filename);
  if (refreshedAsset?.browser_download_url) {
    return {
      downloadUrl: refreshedAsset.browser_download_url,
      source: 'metadata-refresh',
      asset: refreshedAsset
    };
  }

  // Try alternate tag formats (with or without leading v)
  const altVersion = version.startsWith('v') ? version.substring(1) : `v${version}`;
  console.log('Trying alternate version', {
    version,
    altVersion
  });
  if (altVersion !== version) {
    const altMetadata = await getReleaseMetadata(env, altVersion);
    console.log('Alternate metadata lookup', {
      altVersion,
      hasMetadata: Boolean(altMetadata),
      assetCount: altMetadata?.assets?.length || 0
    });
    const altAsset = altMetadata?.assets?.find(asset => asset?.name === filename);
    if (altAsset?.browser_download_url) {
      return {
        downloadUrl: altAsset.browser_download_url,
        source: 'metadata-alt',
        asset: altAsset
      };
    }

    const altDirectUrl = `https://github.com/${owner}/${repo}/releases/download/${altVersion}/${encodeURIComponent(filename)}`;
    const altHead = await fetch(altDirectUrl, {
      method: 'HEAD',
      headers: buildGithubHeaders(env)
    });
    console.log('Alternate direct HEAD check', {
      url: altDirectUrl,
      status: altHead.status,
      ok: altHead.ok
    });
    if (altHead.ok || altHead.status === 302) {
      return {
        downloadUrl: altDirectUrl,
        source: 'direct-alt-head'
      };
    }
  }

  return {
    downloadUrl: null,
    source: 'unresolved',
    details: {
      reason: 'not_found',
      version,
      filename
    }
  };
}

async function getReleaseMetadata(env, version, options = {}) {
  if (!version) {
    return null;
  }

  const { forceRefresh = false } = options;
  const cacheKey = `release_meta:${version}`;

  if (!forceRefresh) {
    const cached = await env.RELEASE_CACHE.get(cacheKey, 'json');
    console.log('KV metadata cache lookup', {
      version,
      cacheHit: Boolean(cached)
    });
    if (cached) {
      return cached;
    }
  }

  const apiUrl = `https://api.github.com/repos/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/releases/tags/${version}`;
  const headers = buildGithubHeaders(env, {
    Accept: 'application/vnd.github.v3+json'
  });

  try {
    const response = await fetch(apiUrl, { headers });
    if (!response.ok) {
      const logContext = {
        version,
        status: response.status
      };
      if (response.status === 401 || response.status === 403) {
        console.warn('Release metadata fetch unauthorized', {
          ...logContext,
          hasToken: Boolean(env.GITHUB_TOKEN)
        });
      } else {
        console.error('Release metadata fetch failed', logContext);
      }

      // Don't spam logs on repeated 404s when versions truly missing
      if (response.status !== 404) {
        const bodyText = await response.text();
        const details = describeGithubFailure(response, bodyText, env);
        console.error('GitHub release metadata fetch failed:', {
          version,
          details
        });
      }
      return null;
    }

    const metadata = await response.json();
    console.log('Fetched metadata from GitHub', {
      version,
      assetCount: metadata?.assets?.length || 0
    });
    await env.RELEASE_CACHE.put(cacheKey, JSON.stringify(metadata), {
      expirationTtl: 600 // 10 minutes
    });
    return metadata;
  } catch (error) {
    console.error('Error fetching release metadata', {
      version,
      error: error?.message || error
    });
    return null;
  }
}

function getContentType(filename) {
  const ext = filename.toLowerCase().split('.').pop();
  
  const mimeTypes = {
    'tar.gz': 'application/gzip',
    'tgz': 'application/gzip',
    'zip': 'application/zip',
    'exe': 'application/octet-stream',
    'deb': 'application/vnd.debian.binary-package',
    'rpm': 'application/x-rpm',
    'dmg': 'application/x-apple-diskimage',
    'pkg': 'application/x-newton-compatible-pkg',
    'msi': 'application/x-msi',
    'sig': 'application/pgp-signature',
    'asc': 'text/plain',
    'sha256': 'text/plain',
    'md5': 'text/plain'
  };

  // Handle compound extensions
  if (filename.endsWith('.tar.gz')) {
    return mimeTypes['tar.gz'];
  }

  return mimeTypes[ext] || 'application/octet-stream';
}

async function recordDownload(request, env, version, filename, size) {
  try {
    const timestamp = Date.now();
    const country = request.cf?.country || 'unknown';
    const userAgent = request.headers.get('User-Agent') || 'unknown';
    
    const downloadData = {
      timestamp,
      version,
      filename,
      size,
      country,
      userAgent: hashUserAgent(userAgent), // Hash for privacy
      ip_hash: await hashIP(request.headers.get('CF-Connecting-IP'))
    };

    const analyticsKey = `download:${timestamp}:${Math.random().toString(36).substr(2, 9)}`;
    
    await env.ANALYTICS.put(analyticsKey, JSON.stringify(downloadData), {
      expirationTtl: 2592000 // 30 days
    });

    // Also update aggregate stats
    const dailyKey = `daily_downloads:${new Date().toISOString().split('T')[0]}`;
    const currentCount = await env.ANALYTICS.get(dailyKey) || '0';
    await env.ANALYTICS.put(dailyKey, (parseInt(currentCount) + 1).toString(), {
      expirationTtl: 2592000 // 30 days
    });

  } catch (error) {
    console.error('Error recording download:', error);
  }
}

function hashUserAgent(userAgent) {
  // Simple hash to anonymize user agent while preserving some analytics value
  const platform = userAgent.toLowerCase();
  if (platform.includes('windows')) return 'windows';
  if (platform.includes('mac')) return 'macos';
  if (platform.includes('linux')) return 'linux';
  if (platform.includes('curl')) return 'curl';
  if (platform.includes('wget')) return 'wget';
  if (platform.includes('powershell')) return 'powershell';
  return 'other';
}

async function hashIP(ip) {
  if (!ip) return 'unknown';
  
  // Create a simple hash of the IP for privacy
  const encoder = new TextEncoder();
  const data = encoder.encode(ip + 'salt_string_here');
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substr(0, 16);
}

export const __testables__ = {
  resolveDownloadSource,
  getReleaseMetadata
};