import {
  detectPlatform,
  detectArchitecture,
  normalizePlatformHint,
  normalizeArchitectureHint
} from '../utils/platform.js';
import { getInstallTemplate } from '../utils/templates.js';
import { corsHeaders } from '../utils/cors.js';

export async function installHandler(request, env) {
  try {
    const url = new URL(request.url);
    const userAgent = request.headers.get('User-Agent') || '';
    const country = request.cf?.country || 'US';
    const pathname = url.pathname;

    // Determine script type from URL
  let scriptType;
  if (pathname.endsWith('.ps1')) {
    scriptType = 'powershell';
  } else if (pathname.endsWith('install-macos.sh')) {
    scriptType = 'macos';
  } else {
    scriptType = 'bash';
  }
    
    const platformOverride = normalizePlatformHint(
      url.searchParams.get('platform') ||
      url.searchParams.get('os') ||
      request.headers.get('X-Install-Platform') ||
      request.headers.get('X-Platform')
    );

    const architectureOverride = normalizeArchitectureHint(
      url.searchParams.get('arch') ||
      url.searchParams.get('architecture') ||
      request.headers.get('X-Install-Arch') ||
      request.headers.get('X-Architecture')
    );

    const platformDetection = scriptType === 'macos'
      ? { platform: 'macos', confidence: 'high' }
      : detectPlatform(userAgent, scriptType);

    const platform = platformOverride || platformDetection.platform;
    const platformConfidence = platformOverride ? 'override' : platformDetection.confidence;
    const architecture = architectureOverride || detectArchitecture(userAgent);
    
    // Get query parameters
    const sandboxParam = (url.searchParams.get('sandbox') || '').toLowerCase();
    const params = {
      version: url.searchParams.get('version') || 'latest',
      verbose: url.searchParams.has('verbose') || url.searchParams.has('v'),
      force: url.searchParams.has('force'),
      installDir: url.searchParams.get('install-dir') || url.searchParams.get('dir'),
      dryRun: url.searchParams.has('dry-run'),
      writableDirs:
        url.searchParams.get('writable-dirs') ||
        url.searchParams.get('rw-dirs') ||
        '',
      disableSandbox:
        url.searchParams.has('no-sandbox') ||
        sandboxParam === '0' ||
        sandboxParam === 'false'
    };

    // Select best mirror based on location and connectivity
    const mirror = await selectBestMirror(country, env);
    
    // Generate customized installation script
    const script = await getInstallTemplate(scriptType, {
      platform,
      platformConfidence,
      architecture,
      country,
      mirror,
      params,
      baseUrl: `https://${url.host}`
    });

    // Set appropriate content type and headers
    const contentType = scriptType === 'powershell' 
      ? 'application/x-powershell; charset=utf-8'
      : 'application/x-sh; charset=utf-8';

    return new Response(script, {
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'private, max-age=0, no-cache, no-store',
        'Vary': 'User-Agent, CF-IPCountry',
        'X-Platform': platform,
        'X-Platform-Confidence': platformConfidence,
        'X-Architecture': architecture,
        'X-Mirror': mirror.name,
        ...corsHeaders
      }
    });

  } catch (error) {
    console.error('Install handler error:', error);
    
    return new Response('Error generating installation script', {
      status: 500,
      headers: {
        'Content-Type': 'text/plain',
        ...corsHeaders
      }
    });
  }
}

// Mirror selection logic
async function selectBestMirror(country, env) {
  const mirrors = {
    proxy: {
      name: 'cloudflare-proxy',
      url: `https://${env.CURRENT_HOST || 'install.lets-script.com'}/releases/proxy`,
      regions: ['all']
    },
    github: {
      name: 'github-direct',
      url: 'https://github.com',
      regions: ['fallback']
    }
  };

  // Always use Cloudflare proxy for all regions
  // This ensures consistent downloads and avoids external mirror issues
  return mirrors.proxy;
}

// A/B testing for different installation approaches
function shouldUseExperimentalFeature(request, feature) {
  const ip = request.headers.get('CF-Connecting-IP') || '';
  const hash = simpleHash(ip + feature);
  
  // Use modulo to determine if user is in test group (10% of users)
  return hash % 10 === 0;
}

function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return Math.abs(hash);
}
