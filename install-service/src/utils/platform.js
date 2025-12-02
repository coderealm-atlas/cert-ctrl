const FREEBSD_MARKERS = ['freebsd', 'dragonfly', 'midnightbsd', 'trueos', 'libfetch'];

function hasFreeBSDHints(ua) {
  return FREEBSD_MARKERS.some(marker => ua.includes(marker));
}

export function detectPlatform(userAgent = '', scriptType = 'bash') {
  const ua = userAgent.toLowerCase();

  if (scriptType === 'powershell') {
    return {
      platform: 'windows',
      confidence: 'high'
    };
  }

  if (scriptType === 'macos') {
    return {
      platform: 'macos',
      confidence: 'high'
    };
  }
  
  if (ua.includes('windows') || ua.includes('win32') || ua.includes('win64')) {
    return {
      platform: 'windows',
      confidence: 'high'
    };
  }
  
  if (ua.includes('macintosh') || ua.includes('darwin') || ua.includes('mac os')) {
    return {
      platform: 'macos',
      confidence: 'high'
    };
  }
  
  if (hasFreeBSDHints(ua)) {
    return {
      platform: 'freebsd',
      confidence: 'high'
    };
  }

  if (ua.includes('linux') || ua.includes('gnu/linux') || ua.includes('x11')) {
    return {
      platform: 'linux',
      confidence: 'high'
    };
  }

  return {
    platform: 'linux',
    confidence: 'low'
  };
}

export function normalizePlatformHint(value) {
  if (!value) {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  if (['linux', 'gnu/linux', 'unix'].includes(normalized)) {
    return 'linux';
  }

  if (['freebsd', 'bsd', 'dragonfly', 'trueos', 'midnightbsd'].includes(normalized)) {
    return 'freebsd';
  }

  if (['mac', 'macos', 'mac os', 'osx', 'darwin'].includes(normalized)) {
    return 'macos';
  }

  if (['win', 'win32', 'win64', 'windows'].includes(normalized)) {
    return 'windows';
  }

  return null;
}

export function normalizeArchitectureHint(value) {
  if (!value) {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  if (['x86_64', 'amd64', 'x64'].includes(normalized)) {
    return 'x64';
  }

  if (['aarch64', 'arm64'].includes(normalized)) {
    return 'arm64';
  }

  if (['armv7', 'armhf', 'arm'].includes(normalized)) {
    return 'arm';
  }

  if (['x86', 'i386', 'i686'].includes(normalized)) {
    return 'x86';
  }

  return null;
}

export function detectArchitecture(userAgent = '') {
  const ua = userAgent.toLowerCase();
  
  // ARM detection
  if (ua.includes('arm64') || ua.includes('aarch64')) {
    return 'arm64';
  }
  
  if (ua.includes('armv7') || ua.includes('armhf')) {
    return 'arm';
  }
  
  // x86 detection
  if (ua.includes('x86_64') || ua.includes('amd64') || ua.includes('win64')) {
    return 'x64';
  }
  
  if (ua.includes('i386') || ua.includes('i686') || ua.includes('x86')) {
    return 'x86';
  }
  
  return 'x64';
}

export function detectShell(userAgent) {
  const ua = userAgent.toLowerCase();
  
  if (ua.includes('powershell')) {
    return 'powershell';
  }
  
  if (ua.includes('bash')) {
    return 'bash';
  }
  
  if (ua.includes('zsh')) {
    return 'zsh';
  }
  
  if (ua.includes('fish')) {
    return 'fish';
  }
  
  if (ua.includes('curl')) {
    return 'bash'; // curl usually pipes to bash
  }
  
  return 'bash'; // Default
}

export function isCI(userAgent, headers) {
  const ua = userAgent.toLowerCase();
  
  // Common CI user agents
  const ciIndicators = [
    'github-actions',
    'travis',
    'circleci',
    'jenkins',
    'gitlab-ci',
    'azure-pipelines',
    'buildkite',
    'teamcity',
    'bamboo'
  ];
  
  return ciIndicators.some(ci => ua.includes(ci));
}

export function isDocker(userAgent, headers) {
  const ua = userAgent.toLowerCase();
  return ua.includes('docker') || ua.includes('container');
}