import { fetchAnalytics } from '../utils/analytics.js';
import { corsHeaders } from '../utils/cors.js';

export async function analyticsHandler(request, env) {
  if (!env || String(env.ANALYTICS_ENABLED).toLowerCase() !== 'true') {
    return new Response(JSON.stringify({ error: 'Analytics disabled' }), {
      status: 404,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }

  try {
    const url = new URL(request.url);
    const type = url.pathname.split('/').pop();
    const payload = await fetchAnalytics(env, type);

    return new Response(JSON.stringify(payload, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        ...corsHeaders
      }
    });
  } catch (error) {
    console.error('Analytics handler failed:', error);
    return new Response(JSON.stringify({ error: 'Failed to load analytics' }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }
}
