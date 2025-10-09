function detectPlatform(userAgent = '') {
  const ua = userAgent.toLowerCase();
  if (ua.includes('windows')) return 'windows';
  if (ua.includes('mac os') || ua.includes('macintosh')) return 'mac';
  if (ua.includes('linux')) return 'linux';
  if (ua.includes('android')) return 'android';
  if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) return 'ios';
  return 'other';
}

export async function trackRequest(request, env) {
  if (!env || String(env.ANALYTICS_ENABLED).toLowerCase() !== 'true') {
    return;
  }

  if (!env.ANALYTICS) {
    console.warn('ANALYTICS binding missing; skipping analytics tracking');
    return;
  }

  try {
    const now = new Date();
    const dateKey = now.toISOString().slice(0, 10); // YYYY-MM-DD
    const url = new URL(request.url);
    const userAgent = request.headers.get('User-Agent') || '';
    const platform = detectPlatform(userAgent);
    const storageKey = `stats:${dateKey}`;

    const existing = await env.ANALYTICS.get(storageKey);
    let record;
    if (existing) {
      try {
        record = JSON.parse(existing);
      } catch (error) {
        console.error('Failed to parse analytics record', error);
        record = { total: 0, paths: {}, platforms: {} };
      }
    } else {
      record = { total: 0, paths: {}, platforms: {} };
    }

    record.total += 1;
    record.paths[url.pathname] = (record.paths[url.pathname] || 0) + 1;
    record.platforms[platform] = (record.platforms[platform] || 0) + 1;
    record.updatedAt = now.toISOString();

    await env.ANALYTICS.put(storageKey, JSON.stringify(record), {
      expirationTtl: Number(env.ANALYTICS_RETENTION_DAYS || 45) * 24 * 60 * 60
    });
  } catch (error) {
    console.error('Analytics tracking failed:', error);
  }
}

export async function fetchAnalytics(env, type) {
  if (!env || !env.ANALYTICS) {
    return { error: 'Analytics storage not configured' };
  }

  const prefix = 'stats:';
  const allKeys = await env.ANALYTICS.list({ prefix, limit: 1000 });
  const records = [];

  for (const { name } of allKeys.keys) {
    const value = await env.ANALYTICS.get(name);
    if (!value) continue;

    try {
      const parsed = JSON.parse(value);
      records.push({
        date: name.substring(prefix.length),
        ...parsed
      });
    } catch (error) {
      console.error('Failed to parse analytics entry', name, error);
    }
  }

  if (type === 'platforms') {
    const aggregation = {};
    for (const record of records) {
      for (const [platform, count] of Object.entries(record.platforms || {})) {
        aggregation[platform] = (aggregation[platform] || 0) + count;
      }
    }
    return { platforms: aggregation };
  }

  // default to daily stats
  return {
    days: records
      .sort((a, b) => (a.date < b.date ? 1 : -1))
      .map(record => ({
        date: record.date,
        total: record.total || 0,
        paths: record.paths || {},
        platforms: record.platforms || {}
      }))
  };
}
