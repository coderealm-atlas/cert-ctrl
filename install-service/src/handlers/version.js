import { corsHeaders } from '../utils/cors.js';
import { buildGithubHeaders, describeGithubFailure } from '../utils/github.js';
import { classifyUpdateUrgency, compareVersions } from '../utils/versioning.js';

export async function versionHandler(request, env) {
  try {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (pathname.includes('/latest')) {
      return await handleLatestVersion(request, env);
    } else if (pathname.includes('/check')) {
      return await handleVersionCheck(request, env);
    }

    return new Response('Invalid version endpoint', { 
      status: 400,
      headers: corsHeaders
    });

  } catch (error) {
    console.error('Version handler error:', error);
    
    return new Response('Error processing version request', {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }
}

async function handleLatestVersion(request, env) {
  try {
    // Check cache first
    const cacheKey = 'latest_release';
    let releaseData = await env.RELEASE_CACHE.get(cacheKey, 'json');

    if (!releaseData) {
      // Fetch from GitHub API
      const apiUrl = `https://api.github.com/repos/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/releases/latest`;
      const headers = buildGithubHeaders(env, {
        Accept: 'application/vnd.github.v3+json'
      });

      const response = await fetch(apiUrl, { headers });

      if (!response.ok) {
        const bodyText = await response.text();
        const details = describeGithubFailure(response, bodyText, env);
        console.error('GitHub latest release error:', details);
        const error = new Error(`GitHub API error: ${response.status}`);
        error.details = details;
        throw error;
      }

      releaseData = await response.json();

      // Cache for 10 minutes
      await env.RELEASE_CACHE.put(cacheKey, JSON.stringify(releaseData), {
        expirationTtl: 600
      });
    }

    const result = {
      version: releaseData.tag_name,
      published_at: releaseData.published_at,
      prerelease: releaseData.prerelease,
      draft: releaseData.draft,
      download_urls: extractDownloadUrls(releaseData.assets),
      changelog_url: releaseData.html_url,
      install_commands: buildInstallCommands(),
      body: releaseData.body
    };

    return new Response(JSON.stringify(result, null, 2), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=600', // 10 minutes
        ...corsHeaders
      }
    });

  } catch (error) {
    console.error('Latest version error:', error);

    return new Response(JSON.stringify({
      error: 'Failed to fetch latest version',
      message: error.message,
      details: error.details || null
    }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }
}

async function handleVersionCheck(request, env) {
  try {
    const url = new URL(request.url);
    const currentVersion = url.searchParams.get('current') || url.searchParams.get('version');
    const platform = url.searchParams.get('platform') || 'unknown';
    const arch = url.searchParams.get('arch') || 'unknown';

    if (!currentVersion) {
      return new Response(JSON.stringify({
        error: 'Missing current version parameter'
      }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }

    // Get latest version info
    const latestResponse = await handleLatestVersion(request, env);
    const latestData = await latestResponse.json();

    if (latestResponse.status !== 200) {
      return latestResponse;
    }

    const latestVersion = latestData.version;
    const newerVersionAvailable = compareVersions(latestVersion, currentVersion) > 0;

    const result = {
      current_version: currentVersion,
      latest_version: latestVersion,
      newer_version_available: newerVersionAvailable,
      platform: platform,
      architecture: arch,
      download_urls: latestData.download_urls,
      install_commands: latestData.install_commands || buildInstallCommands(),
      changelog_url: latestData.changelog_url,
      security_update: await isSecurityUpdate(latestData.body),
      minimum_supported_version: await getMinimumSupportedVersion(env),
      deprecation_warnings: await getDeprecationWarnings(currentVersion, env),
      update_urgency: await getUpdateUrgency(currentVersion, latestVersion, latestData.body, env)
    };

    return new Response(JSON.stringify(result, null, 2), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=300', // 5 minutes
        ...corsHeaders
      }
    });

  } catch (error) {
    console.error('Version check error:', error);
    
    return new Response(JSON.stringify({
      error: 'Failed to check version',
      message: error.message
    }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }
}

function extractDownloadUrls(assets) {
  const urls = {};
  
  assets.forEach(asset => {
    const name = asset.name.toLowerCase();
    if (name.endsWith('.sha256') || name.endsWith('.sig')) {
      return;
    }

    if (name.includes('linux') && name.includes('musl') && name.includes('x64')) {
      urls['linux-musl-x64'] = asset.browser_download_url;
      return;
    }

    if (name.includes('linux') && name.includes('x64') && name.includes('openssl3')) {
      urls['linux-x64-openssl3'] = asset.browser_download_url;
      return;
    }

    if (name.includes('linux') && name.includes('x64')) {
      urls['linux-x64'] = asset.browser_download_url;
      return;
    }

    if (name.includes('linux') && name.includes('arm64')) {
      urls['linux-arm64'] = asset.browser_download_url;
      return;
    }

    if (name.includes('windows') && name.includes('x64')) {
      urls['windows-x64'] = asset.browser_download_url;
      return;
    }

    if (name.includes('macos') && name.includes('x64')) {
      urls['macos-x64'] = asset.browser_download_url;
      return;
    }

    if (name.includes('macos') && name.includes('arm64')) {
      urls['macos-arm64'] = asset.browser_download_url;
    }
  });
  
  return urls;
}

function buildInstallCommands() {
  return {
    linux: 'curl -fsSL "https://install.lets-script.com/install.sh" | sudo bash',
    macos: 'curl -fsSL "https://install.lets-script.com/install-macos.sh" | sudo bash',
    windows: 'irm "https://install.lets-script.com/install.ps1" | iex'
  };
}

export const __testables__ = {
  buildInstallCommands,
  extractDownloadUrls
};

async function isSecurityUpdate(releaseBody) {
  if (!releaseBody) return false;
  
  const securityKeywords = [
    'security', 'vulnerability', 'cve', 'exploit', 
    'patch', 'hotfix', 'critical', 'urgent'
  ];
  
  const bodyLower = releaseBody.toLowerCase();
  return securityKeywords.some(keyword => bodyLower.includes(keyword));
}

async function getMinimumSupportedVersion(env) {
  // This could be stored in KV store and updated as needed
  // Production: wrangler kv:key put --binding CONFIG minimum_supported_version v1.5.0 --env production
  const config = await env.CONFIG?.get('minimum_supported_version');
  return config || 'v0.0.1';
}

async function getDeprecationWarnings(currentVersion, env) {
  // Check if current version has any deprecation warnings
  const warnings = await env.CONFIG?.get('deprecation_warnings', 'json') || {};
  return warnings[currentVersion] || [];
}

async function getUpdateUrgency(currentVersion, latestVersion, releaseBody, env) {
  return classifyUpdateUrgency({
    currentVersion,
    latestVersion,
    minimumSupportedVersion: await getMinimumSupportedVersion(env),
    securityUpdate: await isSecurityUpdate(releaseBody)
  });
}
