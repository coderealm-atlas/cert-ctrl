#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getInstallTemplate } from '../src/utils/templates.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');

const outputDir = resolve(projectRoot, 'dist');
const outputPath = resolve(outputDir, 'install.sh');

async function main() {
  const script = await getInstallTemplate('bash', {
    platform: process.env.PLATFORM || 'linux',
    platformConfidence: process.env.PLATFORM_CONFIDENCE || 'high',
    architecture: process.env.ARCH || 'x64',
    country: process.env.COUNTRY || 'US',
    mirror: {
      name: process.env.MIRROR_NAME || 'local-test',
      url: process.env.MIRROR_URL || 'https://install.lets-script.com/releases/proxy'
    },
    params: {
      version: process.env.VERSION || 'latest',
      verbose: process.env.VERBOSE === 'true',
      force: process.env.FORCE === 'true',
      installDir: process.env.INSTALL_DIR || '',
      dryRun: process.env.DRY_RUN === 'true',
      writableDirs: process.env.WRITABLE_DIRS || '',
      disableSandbox: process.env.SANDBOX_DISABLED === 'true'
    },
    baseUrl: process.env.BASE_URL || 'https://install.lets-script.com'
  });

  mkdirSync(outputDir, { recursive: true });
  writeFileSync(outputPath, script, { mode: 0o755 });

  console.log(`Wrote ${outputPath}`);
  console.log('Run: bash -n', outputPath, 'to syntax-check.');
}

main().catch((err) => {
  console.error('Failed to render install script:', err);
  process.exit(1);
});
