import express from 'express';
import morgan from 'morgan';
import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
app.set('trust proxy', true);
app.use(morgan('combined'));

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const templatesDir = path.resolve(__dirname, '..', 'templates');
const assetsRoot = process.env.ASSETS_ROOT || path.resolve(process.cwd(), 'assets');
const releasesDir = process.env.RELEASES_DIR || path.join(assetsRoot, 'releases');
const latestFile = process.env.LATEST_FILE || path.join(assetsRoot, 'latest.json');
const defaultVersion = process.env.DEFAULT_VERSION || 'latest';
const port = Number.parseInt(process.env.PORT || '8787', 10);

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,HEAD,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,User-Agent'
};

const templateCache = new Map();

app.use((req, res, next) => {
  res.set(corsHeaders);
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get(['/install.sh', '/install.ps1', '/install-macos.sh'], async (req, res) => {
  try {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const version = sanitizeVersion(req.query.version || req.query.v || defaultVersion);
    const templateName = resolveTemplateName(req.path);
    const template = await loadTemplate(templateName);
    const rendered = renderTemplate(template, {
      BASE_URL: baseUrl,
      VERSION: version
    });

    const contentType = req.path.endsWith('.ps1')
      ? 'application/x-powershell; charset=utf-8'
      : 'application/x-sh; charset=utf-8';

    res.set('Content-Type', contentType);
    res.set('Cache-Control', 'private, max-age=0, no-cache, no-store');
    res.send(rendered);
  } catch (error) {
    res.status(500).type('text/plain').send('Failed to generate install script.');
  }
});

app.get('/api/version/latest', async (req, res) => {
  const latest = await readLatest();
  if (!latest) {
    res.status(404).json({ error: 'latest version not configured' });
    return;
  }

  res.set('Cache-Control', 'public, max-age=300');
  res.json(latest);
});

app.get('/api/version/check', async (req, res) => {
  const current = req.query.current || req.query.version;
  if (!current) {
    res.status(400).json({ error: 'missing current version' });
    return;
  }

  const latest = await readLatest();
  if (!latest?.version) {
    res.status(404).json({ error: 'latest version not configured' });
    return;
  }

  const compare = compareVersions(latest.version, current.toString());
  res.json({
    current_version: current,
    latest_version: latest.version,
    newer_version_available: compare > 0
  });
});

app.head('/releases/proxy/:version/:filename', async (req, res) => {
  const response = await handleRelease(req, res, { headOnly: true });
  if (!response) {
    return;
  }
});

app.get('/releases/proxy/:version/:filename', async (req, res) => {
  const response = await handleRelease(req, res, { headOnly: false });
  if (!response) {
    return;
  }
});

app.get('/', (req, res) => {
  res.json({
    service: 'install-service-selfhost',
    endpoints: {
      install_sh: '/install.sh',
      install_ps1: '/install.ps1',
      install_macos: '/install-macos.sh',
      latest: '/api/version/latest',
      proxy: '/releases/proxy/{version}/{filename}'
    }
  });
});

app.all('*', (req, res) => {
  res.status(404).type('text/plain').send('Not Found');
});

app.listen(port, () => {
  console.log(`install-service-selfhost listening on ${port}`);
});

async function loadTemplate(name) {
  if (templateCache.has(name)) {
    return templateCache.get(name);
  }

  const templatePath = path.join(templatesDir, name);
  const content = await fs.readFile(templatePath, 'utf8');
  templateCache.set(name, content);
  return content;
}

function renderTemplate(content, data) {
  return content.replace(/\{\{([A-Z_]+)\}\}/g, (match, key) => {
    return Object.prototype.hasOwnProperty.call(data, key) ? data[key] : match;
  });
}

function resolveTemplateName(pathname) {
  if (pathname.endsWith('.ps1')) {
    return 'install.ps1.tpl';
  }
  if (pathname.endsWith('install-macos.sh')) {
    return 'install-macos.sh.tpl';
  }
  return 'install.sh.tpl';
}

function sanitizeVersion(value) {
  if (!value || typeof value !== 'string') {
    return defaultVersion;
  }
  const trimmed = value.trim();
  return trimmed.length ? trimmed : defaultVersion;
}

async function readLatest() {
  try {
    const raw = await fs.readFile(latestFile, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    return null;
  }
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

function compareVersions(a, b) {
  const aParts = normalizeVersion(a);
  const bParts = normalizeVersion(b);
  const maxLen = Math.max(aParts.length, bParts.length);

  for (let i = 0; i < maxLen; i += 1) {
    const av = aParts[i] ?? 0;
    const bv = bParts[i] ?? 0;
    if (av > bv) {
      return 1;
    }
    if (av < bv) {
      return -1;
    }
  }
  return 0;
}

function normalizeVersion(version) {
  const cleaned = version.toString().trim().replace(/^v/i, '');
  return cleaned
    .split(/[.+-]/)
    .map(part => Number.parseInt(part, 10))
    .map(value => (Number.isNaN(value) ? 0 : value));
}
