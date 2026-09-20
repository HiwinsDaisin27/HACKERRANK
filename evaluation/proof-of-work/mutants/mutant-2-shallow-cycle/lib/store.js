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
  validateStore(data);
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

/** BUG: only detect direct 2-node cycles on save/load */
function detectGroupCycle(groups) {
  for (const [gid, g] of Object.entries(groups)) {
    for (const m of g.members || []) {
      if (groups[m]?.members?.includes(gid)) {
        throw corruptError('group membership cycle detected');
      }
    }
  }
}

/** BUG: only detect direct 2-cycles */
export function wouldIntroduceCycle(groups, parentGroupId, memberId) {
  if (!groups[memberId]) return false;
  if (groups[memberId].members.includes(parentGroupId)) {
    return true;
  }
  return false;
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
