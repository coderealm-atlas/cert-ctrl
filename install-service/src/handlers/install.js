import { detectPlatform, detectArchitecture } from '../utils/platform.js';
import { getInstallTemplate } from '../utils/templates.js';
import { corsHeaders } from '../utils/cors.js';

export async function installHandler(request, env) {
  try {
    const url = new URL(request.url);
    const userAgent = request.headers.get('User-Agent') || '';
    const country = request.cf?.country || 'US';
    const pathname = url.pathname;

    // Determine script type from URL
    const scriptType = pathname.endsWith('.ps1') ? 'powershell' : 'bash';
    
    // Extract platform information
    const platform = detectPlatform(userAgent, scriptType);
    const architecture = detectArchitecture(userAgent);
    
    // Get query parameters
    const params = {
      version: url.searchParams.get('version') || 'latest',
      userInstall: url.searchParams.has('user-install') || url.searchParams.has('user'),
      verbose: url.searchParams.has('verbose') || url.searchParams.has('v'),
      force: url.searchParams.has('force'),
      installDir: url.searchParams.get('install-dir') || url.searchParams.get('dir'),
      dryRun: url.searchParams.has('dry-run')
    };

    // Select best mirror based on location and connectivity
    const mirror = await selectBestMirror(country, env);
    
    // Generate customized installation script
    const script = await getInstallTemplate(scriptType, {
      platform,
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
        'Cache-Control': 'public, max-age=300', // 5 minutes
        'X-Platform': platform,
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
    github: {
      name: 'github',
      url: 'https://github.com',
      regions: ['US', 'EU', 'default']
    },
    china: {
      name: 'china-mirror',
      url: 'https://github.com.cnpmjs.org',
      regions: ['CN', 'HK']
    },
    proxy: {
      name: 'cloudflare-proxy',
      url: `https://${env.CURRENT_HOST || 'install.cert-ctrl.com'}/releases/proxy`,
      regions: ['all']
    }
  };

  // For China, prefer local mirror
  if (country === 'CN' || country === 'HK') {
    return mirrors.china;
  }

  // For other regions, use GitHub directly or proxy if configured
  if (env.USE_PROXY_BY_DEFAULT === 'true') {
    return mirrors.proxy;
  }

  return mirrors.github;
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