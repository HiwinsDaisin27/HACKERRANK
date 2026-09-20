import fs from 'fs';
import { normalizeResourcePath, remapResourcePath } from './paths.js';
import {
  emptyStore,
  loadStore,
  saveStore,
  wouldIntroduceCycle,
} from './store.js';
import { queryDecision, formatExplain } from './evaluate.js';

const ACTIONS = new Set(['read', 'write', 'admin']);

function assertId(id, label) {
  if (!id || !/^[a-zA-Z0-9._-]+$/.test(id)) {
    throw new Error(`invalid ${label}`);
  }
}

export function cmdInit(storePath) {
  saveStore(storePath, emptyStore());
}

export function cmdAddPrincipal(storePath, id) {
  assertId(id, 'principal id');
  const store = loadStore(storePath);
  if (store.principals.includes(id)) {
    throw new Error('principal already exists');
  }
  store.principals.push(id);
  store.principals.sort();
  saveStore(storePath, store);
}

export function cmdAddGroup(storePath, id) {
  assertId(id, 'group id');
  const store = loadStore(storePath);
  if (store.groups[id] || store.principals.includes(id)) {
    throw new Error('group already exists or conflicts with principal id');
  }
  store.groups[id] = { members: [] };
  saveStore(storePath, store);
}

export function cmdAddGroupMember(storePath, groupId, memberId) {
  assertId(groupId, 'group id');
  assertId(memberId, 'member id');
  const store = loadStore(storePath);
  if (!store.groups[groupId]) {
    throw new Error('group not found');
  }
  const memberExists =
    store.principals.includes(memberId) || store.groups[memberId];
  if (!memberExists) {
    throw new Error('member not found');
  }
  if (store.groups[groupId].members.includes(memberId)) {
    throw new Error('member already in group');
  }
  /* BUG: persist to disk before validating cycle (bypasses validate-on-save) */
  store.groups[groupId].members.push(memberId);
  fs.writeFileSync(storePath, JSON.stringify(store, null, 2) + '\n', 'utf8');
  if (wouldIntroduceCycle(store.groups, groupId, memberId)) {
    throw new Error('membership would introduce a cycle');
  }
}

export function cmdRemoveGroupMember(storePath, groupId, memberId) {
  assertId(groupId, 'group id');
  assertId(memberId, 'member id');
  const store = loadStore(storePath);
  if (!store.groups[groupId]) {
    throw new Error('group not found');
  }
  const idx = store.groups[groupId].members.indexOf(memberId);
  if (idx === -1) {
    throw new Error('member not in group');
  }
  store.groups[groupId].members.splice(idx, 1);
  saveStore(storePath, store);
}

function addRule(storePath, effect, opts) {
  const {
    principalOrGroup,
    resource,
    action,
    validFrom,
    validUntil,
  } = opts;
  assertId(principalOrGroup, 'principal-or-group id');
  const resourcePath = normalizeResourcePath(resource);
  if (!ACTIONS.has(action)) {
    throw new Error('invalid action');
  }

  const store = loadStore(storePath);
  let target_type;
  if (store.principals.includes(principalOrGroup)) {
    target_type = 'principal';
  } else if (store.groups[principalOrGroup]) {
    target_type = 'group';
  } else {
    throw new Error('principal or group not found');
  }

  if (validFrom) {
    if (Number.isNaN(new Date(validFrom).getTime())) {
      throw new Error('invalid valid-from');
    }
  }
  if (validUntil) {
    if (Number.isNaN(new Date(validUntil).getTime())) {
      throw new Error('invalid valid-until');
    }
  }
  if (validFrom && validUntil) {
    if (new Date(validFrom).getTime() >= new Date(validUntil).getTime()) {
      throw new Error('valid-from must be before valid-until');
    }
  }

  const id = `rule-${store.next_rule_seq++}`;
  store.rules.push({
    id,
    target_type,
    target_id: principalOrGroup,
    resource: resourcePath,
    action,
    effect,
    valid_from: validFrom || null,
    valid_until: validUntil || null,
  });
  saveStore(storePath, store);
  return id;
}

export function cmdGrant(storePath, opts) {
  return addRule(storePath, 'allow', opts);
}

export function cmdDeny(storePath, opts) {
  return addRule(storePath, 'deny', opts);
}

export function cmdRevoke(storePath, ruleId) {
  if (!ruleId) throw new Error('rule-id required');
  const store = loadStore(storePath);
  const idx = store.rules.findIndex((r) => r.id === ruleId);
  if (idx === -1) {
    throw new Error('rule not found');
  }
  store.rules.splice(idx, 1);
  saveStore(storePath, store);
}

export function cmdQuery(storePath, principal, resource, action, at) {
  const store = loadStore(storePath);
  const result = queryDecision(store, principal, resource, action, at);
  return result.decision;
}

export function cmdExplain(storePath, principal, resource, action, at) {
  const store = loadStore(storePath);
  return formatExplain(store, principal, resource, action, at);
}

export function cmdMoveResource(storePath, from, to) {
  const fromPath = normalizeResourcePath(from);
  const toPath = normalizeResourcePath(to);
  if (fromPath === toPath) {
    throw new Error('from and to must differ');
  }
  const store = loadStore(storePath);
  let changed = false;
  for (const rule of store.rules) {
    const remapped = remapResourcePath(rule.resource, fromPath, toPath);
    if (remapped !== rule.resource) {
      rule.resource = remapped;
      changed = true;
    }
  }
  if (!changed) {
    throw new Error('no resources matched from path');
  }
  saveStore(storePath, store);
}
