import { bashTemplate } from '../../templates/install.sh.js';
import { powershellTemplate } from '../../templates/install.ps1.js';
import { macosTemplate } from '../../templates/install-macos.sh.js';

export async function getInstallTemplate(scriptType, options) {
  const {
    platform,
    architecture,
    country,
    mirror,
    params,
    baseUrl
  } = options;

  const defaults = {
    configDir: '/etc/certctrl',
    stateDir: '/var/lib/certctrl',
    installDir: params.installDir || '',
    serviceLabel: '',
    logDir: '/var/log'
  };

  if (scriptType === 'macos') {
    defaults.configDir = '/Library/Application Support/certctrl';
    defaults.stateDir = '/Library/Application Support/certctrl/state';
    defaults.installDir = params.installDir || '/usr/local/bin';
    defaults.serviceLabel = 'com.coderealm.certctrl';
    defaults.logDir = '/var/log';
  }

  // Template variables
  const templateVars = {
    PLATFORM: platform,
    ARCHITECTURE: architecture,
    COUNTRY: country,
    MIRROR_URL: mirror.url,
    MIRROR_NAME: mirror.name,
    BASE_URL: baseUrl,
    VERSION: params.version,
    VERBOSE: params.verbose ? 'true' : 'false',
    FORCE: params.force ? 'true' : 'false',
    INSTALL_DIR: defaults.installDir,
    CONFIG_DIR: defaults.configDir,
    STATE_DIR: defaults.stateDir,
    SERVICE_LABEL: defaults.serviceLabel,
    LOG_DIR: defaults.logDir,
    DRY_RUN: params.dryRun ? 'true' : 'false',
    GITHUB_REPO_OWNER: 'coderealm-atlas',
    GITHUB_REPO_NAME: 'cert-ctrl'
  };

  if (scriptType === 'powershell') {
    return interpolateTemplate(powershellTemplate, templateVars);
  } else if (scriptType === 'macos') {
    return interpolateTemplate(macosTemplate, templateVars);
  } else {
    return interpolateTemplate(bashTemplate, templateVars);
  }
}

function interpolateTemplate(template, vars) {
  let result = template;
  
  for (const [key, value] of Object.entries(vars)) {
    const placeholder = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
    result = result.replace(placeholder, value);
  }
  
  return result;
}