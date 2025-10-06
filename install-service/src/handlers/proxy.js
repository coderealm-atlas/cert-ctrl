import { corsHeaders } from '../utils/cors.js';

export async function proxyHandler(request, env) {
  try {
    const url = new URL(request.url);
    const pathParts = url.pathname.split('/');
    
    // Extract version and filename from URL
    // Format: /releases/proxy/{version}/{filename}
    const version = pathParts[3];
    const filename = pathParts[4];
    
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

    // Construct GitHub download URL
    const githubUrl = `https://github.com/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/releases/download/${actualVersion}/${filename}`;
    
    // Check cache first
    const cacheKey = `release:${actualVersion}:${filename}`;
    let cachedResponse = await env.RELEASE_CACHE.get(cacheKey, 'arrayBuffer');
    
    if (cachedResponse) {
      // Serve from cache
      return new Response(cachedResponse, {
        headers: {
          'Content-Type': getContentType(filename),
          'Cache-Control': 'public, max-age=86400', // 24 hours
          'X-Cache': 'HIT',
          'X-Version': actualVersion,
          ...corsHeaders
        }
      });
    }

    // Fetch from GitHub
    const githubResponse = await fetch(githubUrl, {
      headers: {
        'User-Agent': 'cert-ctrl-install-service/1.0.0'
      }
    });

    if (!githubResponse.ok) {
      return new Response(`Release file not found: ${filename}`, {
        status: githubResponse.status,
        headers: corsHeaders
      });
    }

    const content = await githubResponse.arrayBuffer();
    const contentType = githubResponse.headers.get('Content-Type') || getContentType(filename);

    // Cache the response (for smaller files only, e.g., < 10MB)
    if (content.byteLength < 10 * 1024 * 1024) {
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
        'X-Cache': 'MISS',
        'X-Version': actualVersion,
        'X-Content-Length': content.byteLength.toString(),
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
      const response = await fetch(apiUrl);
      
      if (response.ok) {
        releaseData = await response.json();
        await env.RELEASE_CACHE.put(cacheKey, JSON.stringify(releaseData), {
          expirationTtl: 600 // 10 minutes
        });
      }
    }

    return releaseData?.tag_name;
  } catch (error) {
    console.error('Error getting latest version:', error);
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