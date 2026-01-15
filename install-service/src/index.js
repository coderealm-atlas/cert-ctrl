import { Router } from 'itty-router';
import { installHandler } from './handlers/install.js';
import { uninstallHandler } from './handlers/uninstall.js';
import { versionHandler } from './handlers/version.js';
import { proxyHandler } from './handlers/proxy.js';
import { analyticsHandler } from './handlers/analytics.js';
import { healthHandler } from './handlers/health.js';
import { caBundleHandler } from './handlers/assets.js';
import { rateLimiter } from './utils/rateLimit.js';
import { corsHeaders, handleCORS } from './utils/cors.js';
import { trackRequest } from './utils/analytics.js';
import { buildGithubHeaders, describeGithubFailure } from './utils/github.js';

const router = Router();

// CORS preflight handling
router.options('*', handleCORS);

// Health check endpoint
router.get('/health', healthHandler);

// Installation script endpoints
router.get('/install.sh', rateLimiter, installHandler);
router.get('/install.ps1', rateLimiter, installHandler);
router.get('/install-macos.sh', rateLimiter, installHandler);

// Uninstallation script endpoints
router.get('/uninstall.sh', rateLimiter, uninstallHandler);
router.get('/uninstall.ps1', rateLimiter, uninstallHandler);
router.get('/uninstall-macos.sh', rateLimiter, uninstallHandler);

// Version API endpoints
router.get('/api/version/check', rateLimiter, versionHandler);
router.get('/api/version/latest', rateLimiter, versionHandler);

// Static-ish assets
router.get('/assets/cacert.pem', rateLimiter, caBundleHandler);

// GitHub proxy endpoints for releases
router.get('/releases/proxy/:version/:filename', rateLimiter, proxyHandler);
router.get('/releases/proxy/latest/:filename', rateLimiter, proxyHandler);
router.head('/releases/proxy/:version/:filename', rateLimiter, proxyHandler);
router.head('/releases/proxy/latest/:filename', rateLimiter, proxyHandler);

// Analytics and statistics (optional, for monitoring)
router.get('/api/stats/:type', analyticsHandler);

// Root endpoint with service information
router.get('/', async (request, env) => {
  const response = {
    service: 'cert-ctrl-install-service',
    version: '1.0.0',
    endpoints: {
      'Unix/Linux Install': '/install.sh',
  'macOS Install': '/install-macos.sh',
      'Windows Install': '/install.ps1',
      'Unix/Linux Uninstall': '/uninstall.sh',
  'macOS Uninstall': '/uninstall-macos.sh',
      'Windows Uninstall': '/uninstall.ps1',
      'Version Check': '/api/version/check',
      'Latest Version': '/api/version/latest',
      'Proxy Releases': '/releases/proxy/{version}/{filename}',
      'CA Bundle': '/assets/cacert.pem',
      'Health Check': '/health'
    },
    usage: {
      'Quick Install (Unix)': 'curl -fsSL https://install.lets-script.com/install.sh | bash',
  'Quick Install (macOS)': 'curl -fsSL https://install.lets-script.com/install-macos.sh | sudo bash',
      'Quick Install (Windows)': 'iwr -useb https://install.lets-script.com/install.ps1 | iex',
      'Quick Uninstall (Unix)': 'curl -fsSL https://install.lets-script.com/uninstall.sh | sudo bash',
  'Quick Uninstall (macOS)': 'curl -fsSL https://install.lets-script.com/uninstall-macos.sh | sudo bash',
      'Quick Uninstall (Windows)': 'iwr -useb https://install.lets-script.com/uninstall.ps1 | iex',
      'Version Check': 'curl https://install.lets-script.com/api/version/latest'
    }
  };

  return new Response(JSON.stringify(response, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders
    }
  });
});

// 404 handler
router.all('*', () => {
  return new Response('Not Found', { 
    status: 404,
    headers: corsHeaders
  });
});

// Main worker fetch handler
export default {
  async fetch(request, env, ctx) {
    try {
      // Track request for analytics (if enabled)
      if (env.ANALYTICS_ENABLED) {
        ctx.waitUntil(trackRequest(request, env));
      }

      // Route the request
      const response = await router.handle(request, env, ctx);
      
      // Add security headers
      response.headers.set('X-Content-Type-Options', 'nosniff');
      response.headers.set('X-Frame-Options', 'DENY');
      response.headers.set('X-XSS-Protection', '1; mode=block');
      response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
      
      return response;
    } catch (error) {
      console.error('Worker error:', error);
      
      return new Response('Internal Server Error', {
        status: 500,
        headers: {
          'Content-Type': 'text/plain',
          ...corsHeaders
        }
      });
    }
  },

  // Scheduled handler for maintenance tasks
  async scheduled(event, env, ctx) {
    switch (event.cron) {
      case '0 */6 * * *': // Every 6 hours
        ctx.waitUntil(warmCache(env));
        ctx.waitUntil(cleanupAnalytics(env));
        break;
    }
  }
};

// Cache warming function
async function warmCache(env) {
  try {
    // Pre-fetch latest release info to warm the cache
    const latestUrl = `https://api.github.com/repos/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/releases/latest`;
    const headers = buildGithubHeaders(env, {
      Accept: 'application/vnd.github.v3+json'
    });

    const response = await fetch(latestUrl, { headers });

    if (response.ok) {
      const data = await response.json();
      const cacheKey = 'latest_release';
      await env.RELEASE_CACHE.put(cacheKey, JSON.stringify(data), {
        expirationTtl: 3600 // 1 hour
      });
      console.log('Cache warmed for latest release');
    } else {
      const bodyText = await response.text();
      const details = describeGithubFailure(response, bodyText, env);
      console.warn('Cache warm GitHub lookup failed:', details);
    }
  } catch (error) {
    console.error('Cache warming failed:', error);
  }
}

// Analytics cleanup function
async function cleanupAnalytics(env) {
  try {
    // Clean up old analytics data (keep last 30 days)
    const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
    const cutoffKey = `analytics:${thirtyDaysAgo}`;
    
    // This would require a more sophisticated cleanup mechanism
    // For now, just log the action
    console.log('Analytics cleanup triggered');
  } catch (error) {
    console.error('Analytics cleanup failed:', error);
  }
}
