const DEFAULT_LIMIT = 120;
const DEFAULT_WINDOW_SECONDS = 60;
const buckets = new Map();

function getBucket(key) {
  const now = Date.now();
  const entry = buckets.get(key);
  if (entry && entry.expiresAt > now) {
    return entry;
  }
  const windowSeconds = DEFAULT_WINDOW_SECONDS;
  const expiresAt = now + windowSeconds * 1000;
  const bucket = { count: 0, expiresAt };
  buckets.set(key, bucket);
  return bucket;
}

export async function rateLimiter(request, env) {
  if (!env || String(env.RATE_LIMIT_ENABLED).toLowerCase() !== 'true') {
    return;
  }

  const limit = Number(env.RATE_LIMIT_MAX_REQUESTS || DEFAULT_LIMIT);
  const windowSeconds = Number(env.RATE_LIMIT_WINDOW_SECONDS || DEFAULT_WINDOW_SECONDS);
  const now = Date.now();
  const clientKey = request.headers.get('CF-Connecting-IP') || 'anonymous';

  let bucket = buckets.get(clientKey);
  if (!bucket || bucket.expiresAt <= now) {
    bucket = {
      count: 0,
      expiresAt: now + windowSeconds * 1000
    };
    buckets.set(clientKey, bucket);
  }

  bucket.count += 1;

  if (bucket.count > limit) {
    const retryAfter = Math.max(1, Math.ceil((bucket.expiresAt - now) / 1000));
    return new Response('Too Many Requests', {
      status: 429,
      headers: {
        'Retry-After': String(retryAfter),
        'Content-Type': 'text/plain'
      }
    });
  }
}
