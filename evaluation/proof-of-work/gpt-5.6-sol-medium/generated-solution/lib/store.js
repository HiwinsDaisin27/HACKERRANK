import fs from 'fs';
import path from 'path';

/**
 * Validates identifier format: letters, digits, '.', '_', '-'
 */
export function isValidId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9._-]+$/.test(id);
}

/**
 * Validates resource path: starts with '/', has no empty segments, no trailing slash except '/'
 */
export function isValidResourcePath(p) {
  if (typeof p !== 'string' || !p.startsWith('/')) return false;
  if (p === '/') return true;
  if (p.endsWith('/')) return false;
  const segments = p.slice(1).split('/');
  for (const seg of segments) {
    if (seg === '') return false;
  }
  return true;
}

export function createEmptyStore() {
  return {
    principals: [],
    groups: {}, // groupName -> array of members (principals or groups)
    rules: []
  };
}

/**
 * Loads store from disk. Handles corruption validation.
 * If file does not exist, returns empty store.
 * Exits 3 with exact format if corruption detected.
 */
export function loadStore(storePath) {
  if (!fs.existsSync(storePath)) {
    return createEmptyStore();
  }

  let content;
  try {
    content = fs.readFileSync(storePath, 'utf8');
  } catch (err) {
    failCorruption(`failed to read store file: ${err.message}`);
  }

  let data;
  try {
    data = JSON.parse(content);
  } catch (err) {
    failCorruption(`invalid JSON: ${err.message}`);
  }

  validateStoreStructure(data);
  return data;
}

/**
 * Safely saves the store to disk via atomic write (temp file + rename).
 */
export function saveStore(storePath, store) {
  validateStoreStructure(store);
  const json = JSON.stringify(store, null, 2);
  const dir = path.dirname(storePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const tempPath = storePath + '.' + Math.random().toString(36.substring(2)) + '.tmp';
  try {
    fs.writeFileSync(tempPath, json, 'utf8');
    fs.renameSync(tempPath, storePath);
  } catch (err) {
    if (fs.existsSync(tempPath)) {
      try { fs.unlinkSync(tempPath); } catch {}
    }
    throw new Error(`failed to write store: ${err.message}`);
  }
}

function failCorruption(reason) {
  process.stderr.write(`grantline: store corruption detected: ${reason}\n`);
  process.exit(3);
}

function validateStoreStructure(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    failCorruption('store root must be an object');
  }

  // principals
  if (!Array.isArray(data.principals)) {
    failCorruption('principals must be an array');
  }
  for (const p of data.principals) {
    if (typeof p !== 'string' || !isValidId(p)) {
      failCorruption(`invalid principal id: ${JSON.stringify(p)}`);
    }
  }

  // groups
  if (!data.groups || typeof data.groups !== 'object' || Array.isArray(data.groups)) {
    failCorruption('groups must be an object');
  }
  for (const [gName, members] of Object.entries(data.groups)) {
    if (!isValidId(gName)) {
      failCorruption(`invalid group id: ${JSON.stringify(gName)}`);
    }
    if (!Array.isArray(members)) {
      failCorruption(`group members for ${gName} must be an array`);
    }
    for (const m of members) {
      if (typeof m !== 'string' || !isValidId(m)) {
        failCorruption(`invalid group member id in group ${gName}: ${JSON.stringify(m)}`);
      }
    }
  }

  // rules
  if (!Array.isArray(data.rules)) {
    failCorruption('rules must be an array');
  }
  for (const r of data.rules) {
    if (!r || typeof r !== 'object') {
      failCorruption('rule must be an object');
    }
    if (typeof r.target !== 'string' || !isValidId(r.target)) {
      failCorruption(`invalid rule target: ${JSON.stringify(r.target)}`);
    }
    if (!['read', 'write', 'admin'].includes(r.action)) {
      failCorruption(`invalid rule action: ${JSON.stringify(r.action)}`);
    }
    if (typeof r.resource !== 'string' || !isValidResourcePath(r.resource)) {
      failCorruption(`invalid rule resource path: ${JSON.stringify(r.resource)}`);
    }
    if (!['allow', 'deny'].includes(r.effect)) {
      failCorruption(`invalid rule effect: ${JSON.stringify(r.effect)}`);
    }
    if (r.valid_from !== undefined && r.valid_from !== null) {
      if (typeof r.valid_from !== 'string' || Number.isNaN(Date.parse(r.valid_from))) {
        failCorruption(`invalid valid_from timestamp: ${JSON.stringify(r.valid_from)}`);
      }
    }
    if (r.valid_until !== undefined && r.valid_until !== null) {
      if (typeof r.valid_until !== 'string' || Number.isNaN(Date.parse(r.valid_until))) {
        failCorruption(`invalid valid_until timestamp: ${JSON.stringify(r.valid_until)}`);
      }
    }
  }
}
