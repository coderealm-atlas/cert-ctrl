export class InvalidInstallParameterError extends Error {
  constructor(parameter, message) {
    super(`Invalid ${parameter}: ${message}`);
    this.name = 'InvalidInstallParameterError';
    this.parameter = parameter;
  }
}

const VERSION_PATTERN = /^(?:latest|v?[A-Za-z0-9][A-Za-z0-9._+-]{0,127})$/;
const UNIX_PATH_PATTERN = /^\/[A-Za-z0-9 _./:+,@%=-]{0,1023}$/;
const WINDOWS_PATH_PATTERN = /^[A-Za-z]:[\\/][^\0\r\n"`$]{0,1021}$/;

export function validateInstallTemplateOptions(scriptType, options) {
  const params = options.params || {};
  const version = String(params.version || 'latest');
  if (!VERSION_PATTERN.test(version)) {
    throw new InvalidInstallParameterError(
      'version',
      'expected latest or a release identifier containing only letters, digits, dot, underscore, plus, and hyphen'
    );
  }

  const installDir = String(params.installDir || '');
  if (installDir) {
    const pattern = scriptType === 'powershell' ? WINDOWS_PATH_PATTERN : UNIX_PATH_PATTERN;
    if (!pattern.test(installDir)) {
      throw new InvalidInstallParameterError(
        'install-dir',
        scriptType === 'powershell'
          ? 'expected an absolute Windows path without shell metacharacters'
          : 'expected an absolute Unix path without shell metacharacters'
      );
    }
  }

  return {
    ...options,
    platform: validateLabel(options.platform || 'unknown', 'platform'),
    platformConfidence: validateLabel(options.platformConfidence || 'unknown', 'platform confidence'),
    architecture: validateLabel(options.architecture || 'unknown', 'architecture'),
    country: validateLabel(options.country || 'unknown', 'country'),
    baseUrl: normalizeHttpUrl(options.baseUrl, 'base URL', { originOnly: true }),
    mirror: {
      ...options.mirror,
      name: validateLabel(options.mirror?.name || 'release-proxy', 'mirror name'),
      url: normalizeHttpUrl(options.mirror?.url, 'mirror URL')
    },
    params: {
      ...params,
      version,
      installDir
    }
  };
}

export function parseBooleanFlag(value, present) {
  if (!present) return false;
  if (value === undefined || value === null || value === '') return true;

  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  throw new InvalidInstallParameterError('boolean flag', `unsupported value '${value}'`);
}

function normalizeHttpUrl(value, label, { originOnly = false } = {}) {
  let parsed;
  try {
    parsed = new URL(String(value || ''));
  } catch {
    throw new InvalidInstallParameterError(label, 'expected an absolute HTTP(S) URL');
  }

  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new InvalidInstallParameterError(label, 'expected an HTTP(S) URL without credentials');
  }
  if (/[\0\r\n"'`$]/.test(parsed.href)) {
    throw new InvalidInstallParameterError(label, 'contains unsafe shell characters');
  }

  if (originOnly) return parsed.origin;
  parsed.hash = '';
  return parsed.href.replace(/\/$/, '');
}

function validateLabel(value, label) {
  const normalized = String(value);
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(normalized)) {
    throw new InvalidInstallParameterError(label, 'contains unsupported characters');
  }
  return normalized;
}
