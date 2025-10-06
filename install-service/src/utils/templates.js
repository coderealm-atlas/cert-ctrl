import { bashTemplate } from '../../templates/install.sh.js';
import { powershellTemplate } from '../../templates/install.ps1.js';

export async function getInstallTemplate(scriptType, options) {
  const {
    platform,
    architecture,
    country,
    mirror,
    params,
    baseUrl
  } = options;

  // Template variables
  const templateVars = {
    PLATFORM: platform,
    ARCHITECTURE: architecture,
    COUNTRY: country,
    MIRROR_URL: mirror.url,
    MIRROR_NAME: mirror.name,
    BASE_URL: baseUrl,
    VERSION: params.version,
    USER_INSTALL: params.userInstall ? 'true' : 'false',
    VERBOSE: params.verbose ? 'true' : 'false',
    FORCE: params.force ? 'true' : 'false',
    INSTALL_DIR: params.installDir || '',
    DRY_RUN: params.dryRun ? 'true' : 'false',
    GITHUB_REPO_OWNER: 'coderealm-atlas',
    GITHUB_REPO_NAME: 'cert-ctrl'
  };

  if (scriptType === 'powershell') {
    return interpolateTemplate(powershellTemplate, templateVars);
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