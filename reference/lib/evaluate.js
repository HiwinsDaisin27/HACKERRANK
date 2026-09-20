import { pathMatchesRule, pathSpecificity } from './paths.js';
import { groupsForPrincipal, canonicalMembershipPath } from './membership.js';

function parseAt(ts) {
  if (!ts) return new Date();
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) {
    throw new Error('invalid --at timestamp');
  }
  return d;
}

function ruleValidAt(rule, atDate) {
  const t = atDate.getTime();
  if (rule.valid_from) {
    const from = new Date(rule.valid_from).getTime();
    if (Number.isNaN(from) || t < from) return false;
  }
  if (rule.valid_until) {
    const until = new Date(rule.valid_until).getTime();
    if (Number.isNaN(until) || t >= until) return false;
  }
  return true;
}

function ruleAppliesToPrincipal(store, rule, principalId) {
  if (rule.target_type === 'principal' && rule.target_id === principalId) {
    return { via: null, targetKind: 'principal' };
  }
  if (rule.target_type === 'group') {
    const groups = groupsForPrincipal(store, principalId);
    if (groups.includes(rule.target_id)) {
      const via = canonicalMembershipPath(store, principalId, rule.target_id);
      return { via, targetKind: 'group' };
    }
  }
  return null;
}

export function collectMatchingRules(store, principalId, resourcePath, action, atTs) {
  const atDate = parseAt(atTs);
  const matched = [];

  for (const rule of store.rules) {
    if (rule.action !== action) continue;
    if (!pathMatchesRule(resourcePath, rule.resource)) continue;
    if (!ruleValidAt(rule, atDate)) continue;

    const apply = ruleAppliesToPrincipal(store, rule, principalId);
    if (!apply) continue;

    matched.push({
      rule,
      specificity: pathSpecificity(rule.resource),
      via: apply.via,
      targetKind: apply.targetKind,
    });
  }

  return matched;
}

export function decide(matched) {
  if (!matched.length) {
    return { decision: 'DENY', rules: [], reason: 'default_deny' };
  }

  const maxSpec = Math.max(...matched.map((m) => m.specificity));
  const atMax = matched.filter((m) => m.specificity === maxSpec);

  const denies = atMax.filter((m) => m.rule.effect === 'deny');
  if (denies.length) {
    return { decision: 'DENY', rules: denies, reason: 'deny_at_max_specificity' };
  }

  const allows = atMax.filter((m) => m.rule.effect === 'allow');
  return { decision: 'ALLOW', rules: allows, reason: 'allow_at_max_specificity' };
}

export function queryDecision(store, principalId, resourcePath, action, atTs) {
  if (!store.principals.includes(principalId)) {
    throw new Error('unknown principal');
  }
  const matched = collectMatchingRules(store, principalId, resourcePath, action, atTs);
  return decide(matched);
}

export function formatExplainLine(entry) {
  const r = entry.rule;
  const parts = [
    `rule_id=${r.id}`,
    `effect=${r.effect}`,
    `action=${r.action}`,
    `resource=${r.resource}`,
    `specificity=${entry.specificity}`,
    `target_type=${r.target_type}`,
    `target_id=${r.target_id}`,
  ];
  if (r.target_type === 'group' && entry.via) {
    parts.push(`membership_path=${entry.via}`);
  }
  return parts.join(' ');
}

export function formatExplain(store, principalId, resourcePath, action, atTs) {
  const result = queryDecision(store, principalId, resourcePath, action, atTs);
  const lines = [`DECISION: ${result.decision}`];
  if (result.rules.length === 0) {
    lines.push('MATCH: none');
  } else {
    const sorted = [...result.rules].sort((a, b) => a.rule.id.localeCompare(b.rule.id));
    for (const entry of sorted) {
      lines.push(`MATCH: ${formatExplainLine(entry)}`);
    }
  }
  return lines.join('\n') + '\n';
}
