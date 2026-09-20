export function groupsForPrincipal(store, principalId) {
  const result = [];
  const seen = new Set();
  const queue = [];

  for (const [gid, g] of Object.entries(store.groups)) {
    if (g.members.includes(principalId)) {
      queue.push(gid);
    }
  }

  while (queue.length) {
    const gid = queue.shift();
    if (seen.has(gid)) continue;
    seen.add(gid);
    result.push(gid);

    for (const [parentId, g] of Object.entries(store.groups)) {
      if (g.members.includes(gid) && !seen.has(parentId)) {
        queue.push(parentId);
      }
    }
  }

  result.sort();
  return result;
}

/**
 * Paths from target group down through nested groups to a direct principal membership.
 * Each path is outer>inner segments starting at target group id.
 */
export function membershipPathsFromTarget(store, principalId, targetGroupId) {
  if (!store.groups[targetGroupId]) return [];

  const paths = [];

  function walk(gid, prefix) {
    const g = store.groups[gid];
    if (!g) return;
    const chain = [...prefix, gid];
    if (g.members.includes(principalId)) {
      paths.push(chain.join('>'));
    }
    for (const m of g.members) {
      if (store.groups[m]) {
        walk(m, chain);
      }
    }
  }

  walk(targetGroupId, []);
  paths.sort();
  return paths;
}

export function canonicalMembershipPath(store, principalId, targetGroupId) {
  const paths = membershipPathsFromTarget(store, principalId, targetGroupId);
  if (!paths.length) return null;
  return paths[0];
}
