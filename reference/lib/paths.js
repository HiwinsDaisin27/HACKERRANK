export function normalizeResourcePath(p) {
  if (p === '/') return '/';
  const trimmed = p.replace(/\/+$/, '');
  if (!trimmed.startsWith('/')) {
    throw new Error('resource path must start with /');
  }
  if (trimmed.includes('//')) {
    throw new Error('resource path must not contain empty segments');
  }
  return trimmed;
}

export function pathSpecificity(resourcePath) {
  const p = normalizeResourcePath(resourcePath);
  if (p === '/') return 1;
  return p.split('/').filter(Boolean).length;
}

export function pathMatchesRule(resourcePath, ruleResource) {
  const r = normalizeResourcePath(resourcePath);
  const rule = normalizeResourcePath(ruleResource);
  if (rule === '/') return true;
  return r === rule || r.startsWith(rule + '/');
}

export function remapResourcePath(resourcePath, fromPrefix, toPrefix) {
  const r = normalizeResourcePath(resourcePath);
  const from = normalizeResourcePath(fromPrefix);
  const to = normalizeResourcePath(toPrefix);
  if (r === from) return to;
  if (from !== '/' && r.startsWith(from + '/')) {
    return to + r.slice(from.length);
  }
  return r;
}
