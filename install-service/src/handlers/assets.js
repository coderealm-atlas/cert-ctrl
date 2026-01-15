import { corsHeaders } from '../utils/cors.js';

const DEFAULT_CA_BUNDLE_URL = 'https://curl.se/ca/cacert.pem';
const KV_KEY = 'asset:cacert.pem';
const KV_TTL_SECONDS = 7 * 24 * 60 * 60;
const EDGE_TTL_SECONDS = 24 * 60 * 60;

function buildResponse(body, sourceUrl) {
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'application/x-pem-file; charset=utf-8',
      'Cache-Control': `public, max-age=${EDGE_TTL_SECONDS}`,
      'X-CA-Bundle-Source': sourceUrl,
      ...corsHeaders
    }
  });
}

export async function caBundleHandler(request, env, ctx) {
  const cache = caches.default;
  const cacheKey = new Request(new URL(request.url).toString(), request);

  const cached = await cache.match(cacheKey);
  if (cached) {
    return cached;
  }

  if (env?.CONFIG?.get) {
    const kvValue = await env.CONFIG.get(KV_KEY);
    if (kvValue) {
      const response = buildResponse(kvValue, 'kv');
      ctx.waitUntil(cache.put(cacheKey, response.clone()));
      return response;
    }
  }

  const sourceUrl = env?.CA_BUNDLE_URL || DEFAULT_CA_BUNDLE_URL;

  let upstream;
  try {
    upstream = await fetch(sourceUrl, {
      headers: {
        'User-Agent': 'cert-ctrl-install-service'
      }
    });
  } catch (error) {
    return new Response('CA bundle fetch failed', {
      status: 502,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        ...corsHeaders
      }
    });
  }

  if (!upstream.ok) {
    return new Response('CA bundle fetch failed', {
      status: 502,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        ...corsHeaders
      }
    });
  }

  const body = await upstream.text();
  const response = buildResponse(body, sourceUrl);

  if (env?.CONFIG?.put) {
    ctx.waitUntil(env.CONFIG.put(KV_KEY, body, { expirationTtl: KV_TTL_SECONDS }));
  }
  ctx.waitUntil(cache.put(cacheKey, response.clone()));

  return response;
}
