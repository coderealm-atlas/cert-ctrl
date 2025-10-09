import { Router } from 'itty-router';
import { installHandler } from './handlers/install.js';
import { versionHandler } from './handlers/version.js';
import { proxyHandler } from './handlers/proxy.js';
import { analyticsHandler } from './handlers/analytics.js';
import { healthHandler } from './handlers/health.js';
import { rateLimiter } from './utils/rateLimit.js';
import { corsHeaders, handleCORS } from './utils/cors.js';
import { trackRequest } from './utils/analytics.js';

const router = Router();

// CORS preflight handling
router.options('*', handleCORS);

// Health check endpoint
router.get('/health', healthHandler);

// Installation script endpoints
router.get('/install.sh', rateLimiter, installHandler);
router.get('/install.ps1', rateLimiter, installHandler);

// Version API endpoints
router.get('/api/version/check', rateLimiter, versionHandler);
router.get('/api/version/latest', rateLimiter, versionHandler);

// GitHub proxy endpoints for releases
router.get('/releases/proxy/:version/:filename', rateLimiter, proxyHandler);
router.get('/releases/proxy/latest/:filename', rateLimiter, proxyHandler);

// Analytics and statistics (optional, for monitoring)
router.get('/api/stats/:type', analyticsHandler);

// Root endpoint with service information
router.get('/', async (request, env) => {
  const response = {
    service: 'cert-ctrl-install-service',
    version: '1.0.0',
    endpoints: {
      'Unix/Linux Install': '/install.sh',
      'Windows Install': '/install.ps1',
      'Version Check': '/api/version/check',
      'Latest Version': '/api/version/latest',
      'Proxy Releases': '/releases/proxy/{version}/{filename}',
      'Health Check': '/health'
    },
    usage: {
      'Quick Install (Unix)': 'curl -fsSL https://install.lets-script.com/install.sh | bash',
      'Quick Install (Windows)': 'iwr -useb https://install.lets-script.com/install.ps1 | iex',
      'User Install (Unix)': 'curl -fsSL https://install.lets-script.com/install.sh | bash -s -- --user-install',
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
    const response = await fetch(latestUrl);
    
    if (response.ok) {
      const data = await response.json();
      const cacheKey = 'latest_release';
      await env.RELEASE_CACHE.put(cacheKey, JSON.stringify(data), {
        expirationTtl: 3600 // 1 hour
      });
      console.log('Cache warmed for latest release');
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
