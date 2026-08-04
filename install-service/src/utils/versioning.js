export function compareVersions(version1 = '', version2 = '') {
  const a = normalizeVersion(version1);
  const b = normalizeVersion(version2);

  const coreResult = compareTokenLists(a.core, b.core, { missingNumericZero: true });
  if (coreResult !== 0) return coreResult;

  if (a.gitDistance !== null || b.gitDistance !== null) {
    const lhs = a.gitDistance ?? 0;
    const rhs = b.gitDistance ?? 0;
    if (lhs !== rhs) return lhs > rhs ? 1 : -1;
  }

  if (a.qualifiers.length === 0 && b.qualifiers.length === 0) return 0;
  if (a.qualifiers.length === 0) return 1;
  if (b.qualifiers.length === 0) return -1;
  return compareTokenLists(a.qualifiers, b.qualifiers);
}

export function classifyUpdateUrgency({
  currentVersion,
  latestVersion,
  minimumSupportedVersion,
  securityUpdate = false
}) {
  if (securityUpdate) return 'critical';
  if (minimumSupportedVersion && compareVersions(currentVersion, minimumSupportedVersion) < 0) {
    return 'high';
  }
  return compareVersions(latestVersion, currentVersion) > 0 ? 'medium' : 'low';
}

function normalizeVersion(raw) {
  const cleaned = String(raw).trim().replace(/^v/i, '');
  const [coreSegment, ...rest] = cleaned.split('-');
  const gitDescribe = rest.length >= 2 && /^\d+$/.test(rest[0]) && /^g[0-9a-f]+$/i.test(rest[1]);

  return {
    core: tokenize(coreSegment),
    gitDistance: gitDescribe ? Number(rest[0]) : null,
    qualifiers: gitDescribe ? rest.slice(2).flatMap(tokenize) : rest.flatMap(tokenize)
  };
}

function tokenize(segment) {
  return String(segment)
    .split('.')
    .filter(Boolean)
    .map(token => (/^\d+$/.test(token) ? Number(token) : token.toLowerCase()));
}

function compareTokenLists(a, b, { missingNumericZero = false } = {}) {
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    const lhs = a[i] ?? (missingNumericZero ? 0 : undefined);
    const rhs = b[i] ?? (missingNumericZero ? 0 : undefined);
    if (lhs === undefined) return -1;
    if (rhs === undefined) return 1;
    if (lhs === rhs) continue;
    if (typeof lhs === 'number' && typeof rhs === 'number') return lhs > rhs ? 1 : -1;
    if (typeof lhs === 'number') return -1;
    if (typeof rhs === 'number') return 1;
    return lhs > rhs ? 1 : -1;
  }
  return 0;
}
