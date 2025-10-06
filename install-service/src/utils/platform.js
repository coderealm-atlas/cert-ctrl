export function detectPlatform(userAgent, scriptType) {
  const ua = userAgent.toLowerCase();
  
  // If PowerShell script requested, it's Windows
  if (scriptType === 'powershell') {
    return 'windows';
  }
  
  // Detect from User-Agent
  if (ua.includes('windows') || ua.includes('win32') || ua.includes('win64')) {
    return 'windows';
  }
  
  if (ua.includes('macintosh') || ua.includes('darwin') || ua.includes('mac os')) {
    return 'macos';
  }
  
  if (ua.includes('linux')) {
    return 'linux';
  }
  
  // Default fallback based on script type
  return scriptType === 'powershell' ? 'windows' : 'linux';
}

export function detectArchitecture(userAgent) {
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
  
  // Default to x64 for most modern systems
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