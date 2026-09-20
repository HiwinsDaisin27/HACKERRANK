import { isValidId, isValidResourcePath } from './store.js';

/**
 * Computes all groups that a principal belongs to directly or via nested groups.
 */
export function getPrincipalGroups(store, principalId) {
  const visitedGroups = new Set();
  const queue = [];

  // Find all groups where principalId is a direct member
  for (const [gName, members] of Object.entries(store.groups)) {
    if (members.includes(principalId)) {
      queue.push(gName);
    }
  }

  while (queue.length > 0) {
    const currentGroup = queue.shift();
    if (visitedGroups.has(currentGroup)) continue;
    visitedGroups.add(currentGroup);

    // Find any other groups that contain currentGroup as a member
    for (const [gName, members] of Object.entries(store.groups)) {
      if (!visitedGroups.has(gName) && members.includes(currentGroup)) {
        queue.push(gName);
      }
    }
  }

  return visitedGroups;
}

/**
 * Checks if a resource path is an ancestor of (or equal to) the request path.
 * Rule path is ancestor of request path if request path equals rule path 
 * or extends it with more segments.
 */
export function isAncestorOrEqual(rulePath, requestPath) {
  if (rulePath === requestPath) return true;
  if (rulePath === '/') return true;
  if (requestPath.startsWith(rulePath + '/')) return true;
  return false;
}

/**
 * Computes the specificity (depth / number of segments) of a resource path.
 * Path '/' has 1 segment (or depth 1). '/app' has 1 segment. '/app/config' has 2 segments.
 * Wait, let's look at the prompt: 
 * "Treat '/' as the broadest path (one segment). For example, '/app' and '/' both have a single segment; '/app/config' is more specific than '/app'."
 * Let's calculate depth carefully:
 * '/' -> 1 segment
 * '/app' -> 1 segment
 * '/app/config' -> 2 segments
*/
export function getPathDepth(p) {
  if (p === '/') return 1;
  return p.slice(1).split('/').length;
}

/**
 * Determines if a rule is in effect at evaluation instant T (Date object).
 * "At evaluation instant T, a rule is in effect only when T is inside its window: 
 * at or after valid_from (if set), and strictly before valid_until (if set)."
 */
export function isRuleInEffect(rule, evaluationTime) {
  const t = evaluationTime.getTime();

  if (rule.valid_from) {
    const fromTime = Date.parse(rule.valid_from);
    if (t < fromTime) return false;
  }

  if (rule.valid_until) {
    const untilTime = Date.parse(rule.valid_until);
    if (t >= untilTime) return false;
  }

  return true;
}

/**
 * Evaluates authorization query.
 * Returns { result: 'ALLOW' | 'DENY', matchingRules: Array }
 */
export function evaluateQuery(store, principal, action, resource, atTimestamp) {
  const evalTime = atTimestamp ? new Date(atTimestamp) : new Date();
  if (Number.isNaN(evalTime.getTime())) {
    throw new Error(`invalid timestamp: ${atTimestamp}`);
  }

  const userGroups = getPrincipalGroups(store, principal);

  // Find all applicable rules
  const applicable = [];

  for (const rule of store.rules) {
    // 1. Action matches
    if (rule.action !== action) continue;

    // 2. Target match (principal is rule target, or belongs to target group)
    const isTarget = (rule.target === principal) || userGroups.has(rule.target);
    if (!isTarget) continue;

    // 3. Resource path is same or ancestor (rule path is ancestor of request path)
    if (!isAncestorOrEqual(rule.resource, resource)) continue;

    // 4. In effect at T
    if (!isRuleInEffect(rule, evalTime)) continue;

    applicable.push(rule);
  }

  if (applicable.length === 0) {
    return { result: 'DENY', matchingRules: [] };
  }

  // Find max specificity among applicable rules
  let maxDepth = -1;
  for (const rule of applicable) {
    const depth = getPathDepth(rule.resource);
    if (depth > maxDepth) {
      maxDepth = depth;
    }
  }

  // Filter rules at max specificity
  const winningRules = applicable.filter(r => getPathDepth(r.resource) === maxDepth);

  // Check if any deny rule exists at winning specificity level
  const hasDeny = winningRules.some(r => r.effect === 'deny');

  return {
    result: hasDeny ? 'DENY' : 'ALLOW',
    matchingRules: winningRules
  };
}
