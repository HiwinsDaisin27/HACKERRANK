import fs from 'fs';
import path from 'path';
import { normalizeResourcePath } from './paths.js';

const CORRUPT_EXIT = 3;

export function corruptError(message) {
  const err = new Error(message);
  err.code = 'STORE_CORRUPT';
  err.exitCode = CORRUPT_EXIT;
  return err;
}

export function emptyStore() {
  return {
    version: 1,
    principals: [],
    groups: {},
    rules: [],
    next_rule_seq: 1,
  };
}

export function loadStore(storePath) {
  let raw;
  try {
    raw = fs.readFileSync(storePath, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') {
      throw Object.assign(new Error('store file not found'), { exitCode: 1 });
    }
    throw e;
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    throw corruptError('invalid JSON');
  }
  /* BUG: skip integrity validation on load */
  return data;
}

export function validateStore(data) {
  if (!data || typeof data !== 'object') {
    throw corruptError('missing store object');
  }
  if (data.version !== 1) {
    throw corruptError('unsupported store version');
  }
  if (!Array.isArray(data.principals)) {
    throw corruptError('principals must be an array');
  }
  if (!data.groups || typeof data.groups !== 'object') {
    throw corruptError('groups must be an object');
  }
  if (!Array.isArray(data.rules)) {
    throw corruptError('rules must be an array');
  }

  const principalSet = new Set(data.principals);
  const groupIds = new Set(Object.keys(data.groups));

  for (const gid of groupIds) {
    const g = data.groups[gid];
    if (!g || !Array.isArray(g.members)) {
      throw corruptError(`group ${gid} has invalid members`);
    }
    for (const m of g.members) {
      if (!principalSet.has(m) && !groupIds.has(m)) {
        throw corruptError(`dangling group member reference: ${gid} -> ${m}`);
      }
    }
  }

  for (const rule of data.rules) {
    if (!rule.id || !rule.target_type || !rule.target_id) {
      throw corruptError('rule missing required fields');
    }
    if (rule.target_type === 'principal') {
      if (!principalSet.has(rule.target_id)) {
        throw corruptError(`rule ${rule.id} references missing principal ${rule.target_id}`);
      }
    } else if (rule.target_type === 'group') {
      if (!groupIds.has(rule.target_id)) {
        throw corruptError(`rule ${rule.id} references missing group ${rule.target_id}`);
      }
    } else {
      throw corruptError(`rule ${rule.id} has invalid target_type`);
    }
    try {
      normalizeResourcePath(rule.resource);
    } catch {
      throw corruptError(`rule ${rule.id} has invalid resource path`);
    }
  }

  detectGroupCycle(data.groups);
}

function detectGroupCycle(groups) {
  const groupIds = Object.keys(groups);
  const visiting = new Set();
  const visited = new Set();

  function dfs(gid, stack) {
    if (visiting.has(gid)) {
      throw corruptError('group membership cycle detected');
    }
    if (visited.has(gid)) return;
    visiting.add(gid);
    stack.push(gid);
    const members = groups[gid]?.members || [];
    for (const m of members) {
      if (groups[m]) {
        dfs(m, stack);
      }
    }
    stack.pop();
    visiting.delete(gid);
    visited.add(gid);
  }

  for (const gid of groupIds) {
    dfs(gid, []);
  }
}

export function wouldIntroduceCycle(groups, parentGroupId, memberId) {
  if (!groups[memberId]) return false;
  const clone = JSON.parse(JSON.stringify(groups));
  if (!clone[parentGroupId]) clone[parentGroupId] = { members: [] };
  if (!clone[parentGroupId].members.includes(memberId)) {
    clone[parentGroupId].members.push(memberId);
  }
  try {
    detectGroupCycle(clone);
    return false;
  } catch (e) {
    if (e.code === 'STORE_CORRUPT') return true;
    throw e;
  }
}

export function saveStore(storePath, data) {
  validateStore(data);
  const dir = path.dirname(storePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = storePath + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', 'utf8');
  fs.renameSync(tmp, storePath);
}

export function readStoreOrThrow(storePath) {
  return loadStore(storePath);
}
