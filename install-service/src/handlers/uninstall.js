import {
  detectPlatform,
  detectArchitecture,
  normalizePlatformHint,
  normalizeArchitectureHint
} from '../utils/platform.js';
import { getUninstallTemplate } from '../utils/templates.js';
import { corsHeaders } from '../utils/cors.js';

export async function uninstallHandler(request, env) {
  try {
    const url = new URL(request.url);
    const userAgent = request.headers.get('User-Agent') || '';
    const country = request.cf?.country || 'US';
    const pathname = url.pathname;

    let scriptType;
    if (pathname.endsWith('.ps1')) {
      scriptType = 'powershell';
    } else if (pathname.endsWith('uninstall-macos.sh')) {
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

    const platformDetection =
      scriptType === 'macos'
        ? { platform: 'macos', confidence: 'high' }
        : detectPlatform(userAgent, scriptType);

    const platform = platformOverride || platformDetection.platform;
    const platformConfidence = platformOverride ? 'override' : platformDetection.confidence;
    const architecture = architectureOverride || detectArchitecture(userAgent);

    const params = {
      version: url.searchParams.get('version') || 'latest',
      verbose: url.searchParams.has('verbose') || url.searchParams.has('v'),
      force: url.searchParams.has('force'),
      installDir: url.searchParams.get('install-dir') || url.searchParams.get('dir'),
      dryRun: url.searchParams.has('dry-run')
    };

    const script = await getUninstallTemplate(scriptType, {
      platform,
      platformConfidence,
      architecture,
      country,
      mirror: { name: 'n/a', url: '' },
      params,
      baseUrl: `https://${url.host}`
    });

    const contentType =
      scriptType === 'powershell'
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
        ...corsHeaders
      }
    });
  } catch (error) {
    console.error('Uninstall handler error:', error);

    return new Response('Error generating uninstallation script', {
      status: 500,
      headers: {
        'Content-Type': 'text/plain',
        ...corsHeaders
      }
    });
  }
}
