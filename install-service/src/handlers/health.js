import { corsHeaders } from '../utils/cors.js';

export async function healthHandler(request, env) {
  const analyticsEnabled = env && typeof env.ANALYTICS_ENABLED !== 'undefined'
    ? String(env.ANALYTICS_ENABLED).toLowerCase() === 'true'
    : false;
  const rateLimitEnabled = env && typeof env.RATE_LIMIT_ENABLED !== 'undefined'
    ? String(env.RATE_LIMIT_ENABLED).toLowerCase() === 'true'
    : false;

  const status = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: env && env.ENVIRONMENT ? env.ENVIRONMENT : 'production',
    checks: {
      releaseCache: 'unconfigured',
      analytics: analyticsEnabled ? 'enabled' : 'disabled',
      rateLimiting: rateLimitEnabled ? 'enabled' : 'disabled'
    }
  };

  if (env && env.RELEASE_CACHE) {
    try {
      const cached = await env.RELEASE_CACHE.get('latest_release');
      status.checks.releaseCache = cached ? 'hit' : 'miss';
    } catch (error) {
      status.checks.releaseCache = 'error';
      status.status = 'degraded';
      status.error = `Cache check failed: ${error.message}`;
    }
  }

  return new Response(JSON.stringify(status, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...corsHeaders
    }
  });
}
