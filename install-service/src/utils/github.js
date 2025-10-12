const DEFAULT_USER_AGENT = 'cert-ctrl-install-service/1.0.0';

export function buildGithubHeaders(env, extraHeaders = {}) {
  const headers = {
    'User-Agent': DEFAULT_USER_AGENT,
    ...extraHeaders
  };

  const token = env?.GITHUB_TOKEN;
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}

export function describeGithubFailure(response, bodyText, env) {
  let parsed;
  let message = bodyText || '';
  let documentationUrl;

  try {
    parsed = JSON.parse(bodyText);
    if (parsed && typeof parsed === 'object') {
      message = parsed.message || message;
      documentationUrl = parsed.documentation_url || parsed.documentationUrl;
    }
  } catch (error) {
    // Body was not JSON; keep original text.
  }

  const rateLimitRemaining = response.headers.get('X-RateLimit-Remaining');
  const status = response.status;
  const lowerMessage = (message || '').toLowerCase();

  let reason = 'unknown';
  let hint = 'Unexpected response returned by GitHub.';

  if (status === 401) {
    reason = 'unauthorized';
    hint = 'GitHub rejected the token. Double-check that it is valid and not expired.';
  } else if (status === 403) {
    if (rateLimitRemaining === '0' || lowerMessage.includes('rate limit')) {
      reason = 'rate_limit';
      hint = 'GitHub API rate limit exceeded. Wait for the limit to reset or use a token with higher limits.';
    } else {
      reason = 'forbidden';
      hint = env?.GITHUB_TOKEN
        ? 'The GitHub token lacks sufficient permissions for this repository.'
        : 'This repository requires authentication. Provide a GitHub token with repo read access.';
    }
  } else if (status === 404) {
    reason = 'not_found';
    hint = env?.GITHUB_TOKEN
      ? 'Release not found or the token cannot see it. Ensure a release exists and the token has repo scope.'
      : 'Release not found. Supply a GitHub token for private repositories or publish a release.';
  }

  return {
    status,
    message,
    documentationUrl,
    rateLimitRemaining,
    reason,
    hint
  };
}
