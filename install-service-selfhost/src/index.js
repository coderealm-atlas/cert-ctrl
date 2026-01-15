import express from 'express';
import morgan from 'morgan';
import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import { getInstallTemplate, getUninstallTemplate } from './utils/templates.js';
import {
  detectPlatform,
  detectArchitecture,
  normalizePlatformHint,
  normalizeArchitectureHint
} from './utils/platform.js';

const app = express();
app.set('trust proxy', true);
app.use(morgan('combined'));

const assetsRoot = process.env.ASSETS_ROOT || path.resolve(process.cwd(), 'assets');
const releasesDir = process.env.RELEASES_DIR || path.join(assetsRoot, 'releases');
const latestFile = process.env.LATEST_FILE || path.join(assetsRoot, 'latest.json');
const defaultVersion = process.env.DEFAULT_VERSION || 'latest';
const port = Number.parseInt(process.env.PORT || '8787', 10);
const host = process.env.HOST || '0.0.0.0';
const repoOwner = process.env.GITHUB_REPO_OWNER || 'coderealm-atlas';
const repoName = process.env.GITHUB_REPO_NAME || 'cert-ctrl';
const analyticsEnabled = parseEnvBool(process.env.ANALYTICS_ENABLED);
const rateLimitEnabled = parseEnvBool(process.env.RATE_LIMIT_ENABLED);
const rateLimitMax = Number.parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '120', 10);
const rateLimitWindowSeconds = Number.parseInt(process.env.RATE_LIMIT_WINDOW_SECONDS || '60', 10);

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, HEAD, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
  'Access-Control-Max-Age': '86400'
};

const rateLimitBuckets = new Map();
const analyticsStore = new Map();

const DEFAULT_CA_BUNDLE_URL = process.env.CA_BUNDLE_URL || 'https://curl.se/ca/cacert.pem';

app.use((req, res, next) => {
  res.set(corsHeaders);
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '1; mode=block');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.vary('accept-encoding');
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
});

app.use((req, res, next) => {
  if (analyticsEnabled && req.method !== 'OPTIONS') {
    trackRequest(req);
  }
  next();
});

app.get('/health', async (req, res) => {
  const status = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: process.env.ENVIRONMENT || 'production',
    checks: {
      releaseCache: 'unconfigured',
      analytics: analyticsEnabled ? 'enabled' : 'disabled',
      rateLimiting: rateLimitEnabled ? 'enabled' : 'disabled'
    }
  };

  try {
    const latest = await readLatest();
    status.checks.releaseCache = latest ? 'hit' : 'miss';
  } catch (error) {
    status.checks.releaseCache = 'error';
    status.status = 'degraded';
    status.error = `Cache check failed: ${error.message}`;
  }

  res.set('Cache-Control', 'no-store');
  res.json(status);
});

app.get('/assets/cacert.pem', rateLimiter, async (req, res) => {
  const localPath = path.join(assetsRoot, 'cacert.pem');
  try {
    if (fsSync.existsSync(localPath)) {
      const body = await fs.readFile(localPath, 'utf8');
      res.set('Content-Type', 'application/x-pem-file; charset=utf-8');
      res.set('Cache-Control', 'public, max-age=86400');
      res.set('X-CA-Bundle-Source', 'local');
      res.send(body);
      return;
    }
  } catch (error) {
    // Fall through to remote
  }

  try {
    const upstream = await fetch(DEFAULT_CA_BUNDLE_URL, {
      headers: {
        'User-Agent': 'cert-ctrl-install-service-selfhost'
      }
    });
    if (!upstream.ok) {
      res.status(502).type('text/plain').send('CA bundle fetch failed');
      return;
    }
    const body = await upstream.text();
    res.set('Content-Type', 'application/x-pem-file; charset=utf-8');
    res.set('Cache-Control', 'public, max-age=86400');
    res.set('X-CA-Bundle-Source', DEFAULT_CA_BUNDLE_URL);
    res.send(body);
  } catch (error) {
    res.status(502).type('text/plain').send('CA bundle fetch failed');
  }
});

app.get(['/install.sh', '/install.ps1', '/install-macos.sh'], rateLimiter, async (req, res) => {
  try {
    const baseUrl = getBaseUrl(req);
    const scriptType = resolveScriptType(req.path);
    const userAgent = req.get('User-Agent') || '';
    const country = req.get('CF-IPCountry') || req.get('X-Country') || 'US';

    const platformOverride = normalizePlatformHint(
      readQueryString(req.query, 'platform') ||
      readQueryString(req.query, 'os') ||
      req.get('X-Install-Platform') ||
      req.get('X-Platform')
    );

    const architectureOverride = normalizeArchitectureHint(
      readQueryString(req.query, 'arch') ||
      readQueryString(req.query, 'architecture') ||
      req.get('X-Install-Arch') ||
      req.get('X-Architecture')
    );

    const platformDetection = scriptType === 'macos'
      ? { platform: 'macos', confidence: 'high' }
      : detectPlatform(userAgent, scriptType);

    const platform = platformOverride || platformDetection.platform;
    const platformConfidence = platformOverride ? 'override' : platformDetection.confidence;
    const architecture = architectureOverride || detectArchitecture(userAgent);

    const sandboxParam = readQueryString(req.query, 'sandbox')?.toLowerCase() || '';
    const params = {
      version: readQueryString(req.query, 'version') || defaultVersion,
      verbose: hasQueryFlag(req.query, 'verbose') || hasQueryFlag(req.query, 'v'),
      force: hasQueryFlag(req.query, 'force'),
      installDir: readQueryString(req.query, 'install-dir') || readQueryString(req.query, 'dir') || '',
      dryRun: hasQueryFlag(req.query, 'dry-run'),
      writableDirs: readQueryString(req.query, 'writable-dirs') || readQueryString(req.query, 'rw-dirs') || '',
      disableSandbox:
        hasQueryFlag(req.query, 'no-sandbox') ||
        sandboxParam === '0' ||
        sandboxParam === 'false'
    };

    const mirror = selectBestMirror(baseUrl);
    const script = await getInstallTemplate(scriptType, {
      platform,
      platformConfidence,
      architecture,
      country,
      mirror,
      params,
      baseUrl
    });

    const contentType = scriptType === 'powershell'
      ? 'application/x-powershell; charset=utf-8'
      : 'application/x-sh; charset=utf-8';

    res.set('Content-Type', contentType);
    res.set('Cache-Control', 'private, max-age=0, no-cache, no-store');
    res.vary('User-Agent');
    res.vary('CF-IPCountry');
    res.set('X-Platform', platform);
    res.set('X-Platform-Confidence', platformConfidence);
    res.set('X-Architecture', architecture);
    res.set('X-Mirror', mirror.name);
    res.send(script);
  } catch (error) {
    res.status(500).type('text/plain').send('Error generating installation script');
  }
});

app.get(['/uninstall.sh', '/uninstall.ps1', '/uninstall-macos.sh'], rateLimiter, async (req, res) => {
  try {
    const baseUrl = getBaseUrl(req);
    const scriptType = resolveScriptType(req.path);
    const userAgent = req.get('User-Agent') || '';
    const country = req.get('CF-IPCountry') || req.get('X-Country') || 'US';

    const platformOverride = normalizePlatformHint(
      readQueryString(req.query, 'platform') ||
      readQueryString(req.query, 'os') ||
      req.get('X-Install-Platform') ||
      req.get('X-Platform')
    );

    const architectureOverride = normalizeArchitectureHint(
      readQueryString(req.query, 'arch') ||
      readQueryString(req.query, 'architecture') ||
      req.get('X-Install-Arch') ||
      req.get('X-Architecture')
    );

    const platformDetection = scriptType === 'macos'
      ? { platform: 'macos', confidence: 'high' }
      : detectPlatform(userAgent, scriptType);

    const platform = platformOverride || platformDetection.platform;
    const platformConfidence = platformOverride ? 'override' : platformDetection.confidence;
    const architecture = architectureOverride || detectArchitecture(userAgent);

    const params = {
      version: readQueryString(req.query, 'version') || defaultVersion,
      verbose: hasQueryFlag(req.query, 'verbose') || hasQueryFlag(req.query, 'v'),
      force: hasQueryFlag(req.query, 'force'),
      installDir: readQueryString(req.query, 'install-dir') || readQueryString(req.query, 'dir') || '',
      dryRun: hasQueryFlag(req.query, 'dry-run')
    };

    const mirror = selectBestMirror(baseUrl);
    const script = await getUninstallTemplate(scriptType, {
      platform,
      platformConfidence,
      architecture,
      country,
      mirror,
      params,
      baseUrl
    });

    const contentType = scriptType === 'powershell'
      ? 'application/x-powershell; charset=utf-8'
      : 'application/x-sh; charset=utf-8';

    res.set('Content-Type', contentType);
    res.set('Cache-Control', 'private, max-age=0, no-cache, no-store');
    res.vary('User-Agent');
    res.vary('CF-IPCountry');
    res.set('X-Platform', platform);
    res.set('X-Platform-Confidence', platformConfidence);
    res.set('X-Architecture', architecture);
    res.set('X-Mirror', mirror.name);
    res.send(script);
  } catch (error) {
    res.status(500).type('text/plain').send('Error generating uninstall script');
  }
});

app.get('/api/version/latest', rateLimiter, async (req, res) => {
  const latest = await readLatest();
  if (!latest?.version) {
    res.status(404).json({ error: 'latest version not configured' });
    return;
  }

  const baseUrl = getBaseUrl(req);
  const payload = buildLatestResponse(latest, baseUrl);

  res.set('Cache-Control', 'public, max-age=600');
  res.json(payload);
});

app.get('/api/version/check', rateLimiter, async (req, res) => {
  const current = readQueryString(req.query, 'current') || readQueryString(req.query, 'version');
  if (!current) {
    res.status(400).json({ error: 'missing current version' });
    return;
  }

  const latest = await readLatest();
  if (!latest?.version) {
    res.status(404).json({ error: 'latest version not configured' });
    return;
  }

  const baseUrl = getBaseUrl(req);
  const latestPayload = buildLatestResponse(latest, baseUrl);
  const latestVersion = latestPayload.version;

  res.set('Cache-Control', 'public, max-age=300');
  res.json({
    current_version: current,
    latest_version: latestVersion,
    newer_version_available: compareVersions(latestVersion, current) > 0,
    platform: readQueryString(req.query, 'platform') || 'unknown',
    architecture: readQueryString(req.query, 'arch') || 'unknown',
    download_urls: latestPayload.download_urls,
    install_commands: latestPayload.install_commands,
    changelog_url: latestPayload.changelog_url,
    security_update: await isSecurityUpdate(latestPayload.body),
    minimum_supported_version: getMinimumSupportedVersion(),
    deprecation_warnings: getDeprecationWarnings(current),
    update_urgency: await getUpdateUrgency(current, latestVersion, latestPayload.body)
  });
});

app.head(['/releases/proxy/:version/:filename', '/releases/proxy/latest/:filename'], rateLimiter, async (req, res) => {
  const response = await handleRelease(req, res, { headOnly: true });
  if (!response) {
    return;
  }
});

app.get(['/releases/proxy/:version/:filename', '/releases/proxy/latest/:filename'], rateLimiter, async (req, res) => {
  const response = await handleRelease(req, res, { headOnly: false });
  if (!response) {
    return;
  }
});

app.get('/api/stats/:type', (req, res) => {
  if (!analyticsEnabled) {
    res.status(404).json({ error: 'Analytics disabled' });
    return;
  }

  const payload = fetchAnalytics(req.params.type);
  res.set('Cache-Control', 'no-store');
  res.json(payload);
});

app.get('/', (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
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
      'Health Check': '/health'
    },
    usage: {
      'Quick Install (Unix)': `curl -fsSL ${baseUrl}/install.sh | bash`,
      'Quick Install (macOS)': `curl -fsSL ${baseUrl}/install-macos.sh | sudo bash`,
      'Quick Install (Windows)': `iwr -useb ${baseUrl}/install.ps1 | iex`,
      'Quick Uninstall (Unix)': `curl -fsSL ${baseUrl}/uninstall.sh | sudo bash`,
      'Quick Uninstall (macOS)': `curl -fsSL ${baseUrl}/uninstall-macos.sh | sudo bash`,
      'Quick Uninstall (Windows)': `iwr -useb ${baseUrl}/uninstall.ps1 | iex`,
      'Version Check': `curl ${baseUrl}/api/version/latest`
    }
  });
});

app.all('*', (req, res) => {
  res.status(404).type('text/plain').send('Not Found');
});

app.listen(port, host, () => {
  console.log(`install-service-selfhost listening on ${host}:${port}`);
});

function rateLimiter(req, res, next) {
  if (!rateLimitEnabled) {
    next();
    return;
  }

  const now = Date.now();
  const clientKey = req.get('CF-Connecting-IP') || req.ip || 'anonymous';
  let bucket = rateLimitBuckets.get(clientKey);
  if (!bucket || bucket.expiresAt <= now) {
    bucket = {
      count: 0,
      expiresAt: now + rateLimitWindowSeconds * 1000
    };
    rateLimitBuckets.set(clientKey, bucket);
  }

  bucket.count += 1;
  if (bucket.count > rateLimitMax) {
    const retryAfter = Math.max(1, Math.ceil((bucket.expiresAt - now) / 1000));
    res.set('Retry-After', String(retryAfter));
    res.status(429).type('text/plain').send('Too Many Requests');
    return;
  }

  next();
}

function trackRequest(req) {
  const now = new Date();
  const dateKey = now.toISOString().slice(0, 10);
  const userAgent = req.get('User-Agent') || '';
  const platform = detectAnalyticsPlatform(userAgent);

  const existing = analyticsStore.get(dateKey) || {
    total: 0,
    paths: {},
    platforms: {},
    updatedAt: now.toISOString()
  };

  existing.total += 1;
  existing.paths[req.path] = (existing.paths[req.path] || 0) + 1;
  existing.platforms[platform] = (existing.platforms[platform] || 0) + 1;
  existing.updatedAt = now.toISOString();

  analyticsStore.set(dateKey, existing);
}

function fetchAnalytics(type) {
  const records = Array.from(analyticsStore.entries()).map(([date, record]) => ({
    date,
    ...record
  }));

  if (type === 'platforms') {
    const aggregation = {};
    for (const record of records) {
      for (const [platform, count] of Object.entries(record.platforms || {})) {
        aggregation[platform] = (aggregation[platform] || 0) + count;
      }
    }
    return { platforms: aggregation };
  }

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

function detectAnalyticsPlatform(userAgent = '') {
  const ua = userAgent.toLowerCase();
  if (ua.includes('windows')) return 'windows';
  if (ua.includes('mac os') || ua.includes('macintosh')) return 'mac';
  if (ua.includes('freebsd')) return 'freebsd';
  if (ua.includes('linux')) return 'linux';
  if (ua.includes('android')) return 'android';
  if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) return 'ios';
  return 'other';
}

function parseEnvBool(value) {
  if (value === undefined) {
    return false;
  }
  return String(value).toLowerCase() === 'true';
}

function readQueryString(query, key) {
  const value = query?.[key];
  if (Array.isArray(value)) {
    return value[0];
  }
  if (value === undefined || value === null) {
    return '';
  }
  return String(value);
}

function hasQueryFlag(query, key) {
  return Object.prototype.hasOwnProperty.call(query || {}, key);
}

function getBaseUrl(req) {
  return `${req.protocol}://${req.get('host')}`;
}

function resolveScriptType(pathname) {
  if (pathname.endsWith('.ps1')) {
    return 'powershell';
  }
  if (pathname.endsWith('install-macos.sh')) {
    return 'macos';
  }
  return 'bash';
}

function selectBestMirror(baseUrl) {
  const mirrorUrl = process.env.MIRROR_URL || `${baseUrl}/releases/proxy`;
  return {
    name: process.env.MIRROR_NAME || 'cloudflare-proxy',
    url: mirrorUrl,
    regions: ['all']
  };
}

async function readLatest() {
  try {
    const raw = await fs.readFile(latestFile, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    return null;
  }
}

function buildLatestResponse(latest, baseUrl) {
  const version = latest.version || defaultVersion;
  const changelogUrl = latest.changelog_url || (version
    ? `https://github.com/${repoOwner}/${repoName}/releases/tag/${version}`
    : null);
  const downloadUrls = latest.download_urls || extractDownloadUrls(latest.assets || [], baseUrl, version);
  const installCommands = latest.install_commands || buildInstallCommands(baseUrl);

  return {
    version,
    published_at: latest.published_at || latest.updated_at || null,
    prerelease: Boolean(latest.prerelease),
    draft: Boolean(latest.draft),
    download_urls: downloadUrls,
    changelog_url: changelogUrl,
    install_commands: installCommands,
    body: latest.body || null
  };
}

function extractDownloadUrls(assets, baseUrl, version) {
  const urls = {};
  const versionPrefix = version || 'latest';

  assets.forEach(asset => {
    const name = (asset.name || '').toLowerCase();
    if (!name || name.endsWith('.sha256') || name.endsWith('.sig') || name.endsWith('.asc')) {
      return;
    }

    const downloadUrl = `${baseUrl}/releases/proxy/${versionPrefix}/${asset.name}`;

    if (name.includes('linux') && name.includes('musl') && name.includes('x64')) {
      urls['linux-musl-x64'] = downloadUrl;
      return;
    }
    if (name.includes('linux') && name.includes('x64') && name.includes('openssl3')) {
      urls['linux-x64-openssl3'] = downloadUrl;
      return;
    }
    if (name.includes('linux') && name.includes('x64')) {
      urls['linux-x64'] = downloadUrl;
      return;
    }
    if (name.includes('linux') && name.includes('arm64')) {
      urls['linux-arm64'] = downloadUrl;
      return;
    }
    if (name.includes('windows') && name.includes('x64')) {
      urls['windows-x64'] = downloadUrl;
      return;
    }
    if (name.includes('macos') && name.includes('x64')) {
      urls['macos-x64'] = downloadUrl;
      return;
    }
    if (name.includes('macos') && name.includes('arm64')) {
      urls['macos-arm64'] = downloadUrl;
    }
  });

  return urls;
}

function buildInstallCommands(baseUrl) {
  return {
    linux: `curl -fsSL "${baseUrl}/install.sh?force=1" | sudo bash`,
    macos: `curl -fsSL "${baseUrl}/install-macos.sh?force=1" | sudo bash`,
    windows: `irm "${baseUrl}/install.ps1?force=1" | iex`
  };
}

async function handleRelease(req, res, options) {
  const version = req.params.version === 'latest'
    ? await resolveLatestVersion()
    : req.params.version;

  if (!version) {
    res.status(404).json({ error: 'latest version not configured' });
    return null;
  }

  const filename = req.params.filename;
  const filePath = resolveReleasePath(version, filename);
  if (!filePath) {
    res.status(400).json({ error: 'invalid file path' });
    return null;
  }

  try {
    const stats = await fs.stat(filePath);
    if (!stats.isFile()) {
      res.status(404).json({ error: 'asset not found' });
      return null;
    }

    res.set('Content-Type', getContentType(filename));
    res.set('Content-Length', stats.size.toString());
    res.set('Cache-Control', 'public, max-age=86400');
    res.set('X-Version', version);
    res.set('X-Cache', 'MISS');
    res.set('X-Source', 'local');

    if (options.headOnly) {
      res.status(200).end();
      return true;
    }

    const stream = fsSync.createReadStream(filePath);
    stream.on('error', () => {
      res.status(500).end();
    });
    stream.pipe(res);
    return true;
  } catch (error) {
    res.status(404).json({ error: 'asset not found' });
    return null;
  }
}

async function resolveLatestVersion() {
  const latest = await readLatest();
  if (!latest?.version) {
    return null;
  }
  return latest.version;
}

function resolveReleasePath(version, filename) {
  const base = path.resolve(releasesDir, version);
  const target = path.resolve(base, filename);
  if (!target.startsWith(base + path.sep)) {
    return null;
  }
  return target;
}

function getContentType(filename) {
  const lower = filename.toLowerCase();
  if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) {
    return 'application/gzip';
  }
  if (lower.endsWith('.zip')) {
    return 'application/zip';
  }
  if (lower.endsWith('.sha256') || lower.endsWith('.asc') || lower.endsWith('.sig')) {
    return 'text/plain';
  }
  return 'application/octet-stream';
}

function compareVersions(version1 = '', version2 = '') {
  const normalize = (raw) => {
    const cleaned = raw.trim().replace(/^v/i, '');
    const [core, ...rest] = cleaned.split('-');

    const toTokens = (segment) =>
      segment
        .split('.')
        .filter((token) => token.length > 0)
        .map((token) => {
          const numeric = Number(token);
          return Number.isNaN(numeric) ? token : numeric;
        });

    return {
      core: toTokens(core),
      qualifiers: rest.flatMap(toTokens)
    };
  };

  const a = normalize(version1);
  const b = normalize(version2);

  const maxCoreLength = Math.max(a.core.length, b.core.length);
  for (let i = 0; i < maxCoreLength; i++) {
    const lhs = a.core[i] ?? 0;
    const rhs = b.core[i] ?? 0;

    if (typeof lhs === 'number' && typeof rhs === 'number') {
      if (lhs > rhs) return 1;
      if (lhs < rhs) return -1;
    } else {
      const lhsStr = String(lhs);
      const rhsStr = String(rhs);
      if (lhsStr > rhsStr) return 1;
      if (lhsStr < rhsStr) return -1;
    }
  }

  const aHasQualifiers = a.qualifiers.length > 0;
  const bHasQualifiers = b.qualifiers.length > 0;

  if (!aHasQualifiers && !bHasQualifiers) {
    return 0;
  }
  if (!aHasQualifiers && bHasQualifiers) {
    return 1;
  }
  if (aHasQualifiers && !bHasQualifiers) {
    return -1;
  }

  const maxQualifierLength = Math.max(a.qualifiers.length, b.qualifiers.length);
  for (let i = 0; i < maxQualifierLength; i++) {
    const lhs = a.qualifiers[i];
    const rhs = b.qualifiers[i];

    if (lhs === undefined) return -1;
    if (rhs === undefined) return 1;

    const lhsIsNumber = typeof lhs === 'number';
    const rhsIsNumber = typeof rhs === 'number';

    if (lhsIsNumber && rhsIsNumber) {
      if (lhs > rhs) return 1;
      if (lhs < rhs) return -1;
      continue;
    }

    if (lhsIsNumber !== rhsIsNumber) {
      return lhsIsNumber ? -1 : 1;
    }

    const lhsStr = String(lhs);
    const rhsStr = String(rhs);

    if (lhsStr > rhsStr) return 1;
    if (lhsStr < rhsStr) return -1;
  }

  return 0;
}

async function isSecurityUpdate(releaseBody) {
  if (!releaseBody) return false;

  const securityKeywords = [
    'security', 'vulnerability', 'cve', 'exploit',
    'patch', 'hotfix', 'critical', 'urgent'
  ];

  const bodyLower = releaseBody.toLowerCase();
  return securityKeywords.some(keyword => bodyLower.includes(keyword));
}

function getMinimumSupportedVersion() {
  return process.env.MINIMUM_SUPPORTED_VERSION || 'v0.0.1';
}

function getDeprecationWarnings(currentVersion) {
  const raw = process.env.DEPRECATION_WARNINGS_JSON;
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw);
    return parsed[currentVersion] || [];
  } catch (error) {
    return [];
  }
}

async function getUpdateUrgency(currentVersion, latestVersion, releaseBody) {
  const versionGap = compareVersions(latestVersion, currentVersion);

  if (await isSecurityUpdate(releaseBody)) {
    return 'critical';
  }

  if (versionGap >= 2) {
    return 'high';
  } else if (versionGap >= 1) {
    return 'medium';
  }

  return 'low';
}
