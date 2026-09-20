# Raw Model Response

```
===FILE: package.json===
{
  "name": "grantline",
  "version": "1.0.0",
  "description": "Headless command-line authorization CLI",
  "main": "bin/grantline.js",
  "bin": {
    "grantline": "bin/grantline.js"
  },
  "dependencies": {},
  "devDependencies": {},
  "engines": {
    "node": ">=18.0.0"
  }
}
===END FILE===

===FILE: bin/grantline.js===
#!/usr/bin/env node

import { main } from '../lib/cli.js';

main().catch((err) => {
  console.error(`grantline: ${err.message}`);
  process.exit(1);
});
===END FILE===

===FILE: lib/store.js===
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
===END FILE===

===FILE: lib/engine.js===
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
===END FILE===

===FILE: lib/cli.js===
import { loadStore, saveStore, isValidId, isValidResourcePath } from './store.js';
import { evaluateQuery, getPrincipalGroups, getPathDepth } from './engine.js';

export async function main() {
  const args = process.argv.slice(2);
  
  // Parse global flags and subcommand
  let storePath = 'grantline.store';
  let i = 0;

  while (i < args.length) {
    if (args[i] === '--store') {
      if (i + 1 >= args.length) {
        throw new Error('missing value for --store');
      }
      storePath = args[i + 1];
      i += 2;
    } else {
      break;
    }
  }

  const subcommand = args[i];
  const subArgs = args.slice(i + 1);

  if (!subcommand) {
    throw new Error('missing subcommand (principal, group, resource, rule, query, explain)');
  }

  switch (subcommand) {
    case 'principal':
      handlePrincipal(storePath, subArgs);
      break;
    case 'group':
      handleGroup(storePath, subArgs);
      break;
    case 'resource':
      handleResource(storePath, subArgs);
      break;
    case 'rule':
      handleRule(storePath, subArgs);
      break;
    case 'query':
      handleQuery(storePath, subArgs);
      break;
    case 'explain':
      handleExplain(storePath, subArgs);
      break;
    default:
      throw new Error(`unknown subcommand: ${subcommand}`);
  }
}

// Helper to parse sub-flags like --id, --group, etc.
function parseArgs(args) {
  const parsed = { _args: [] };
  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        parsed[key] = args[i + 1];
        i += 2;
      } else {
        parsed[key] = true;
        i += 1;
      }
    } else {
      parsed._args.push(arg);
      i += 1;
    }
  }
  return parsed;
}

// ----------------------------------------------------
// PRINCIPAL
// ----------------------------------------------------
function handlePrincipal(storePath, args) {
  const parsed = parseArgs(args);
  const action = parsed._args[0];

  if (action === 'add') {
    const id = parsed.id;
    if (!id) throw new Error('missing --id');
    if (!isValidId(id)) throw new Error(`invalid principal id: ${id}`);

    const store = loadStore(storePath);
    if (store.principals.includes(id)) {
      throw new Error(`principal already exists: ${id}`);
    }
    store.principals.push(id);
    saveStore(storePath, store);
    process.exit(0);
  } else if (action === 'list') {
    const store = loadStore(storePath);
    for (const p of store.principals) {
      console.log(p);
    }
    process.exit(0);
  } else {
    throw new Error(`unknown principal action: ${action}`);
  }
}

// ----------------------------------------------------
// GROUP
// ----------------------------------------------------
function handleGroup(storePath, args) {
  const parsed = parseArgs(args);
  const action = parsed._args[0];

  if (action === 'add') {
    const id = parsed.id;
    if (!id) throw new Error('missing --id');
    if (!isValidId(id)) throw new Error(`invalid group id: ${id}`);

    const store = loadStore(storePath);
    if (store.groups[id]) {
      throw new Error(`group already exists: ${id}`);
    }
    store.groups[id] = [];
    saveStore(storePath, store);
    process.exit(0);
  } else if (action === 'add-member') {
    const group = parsed.group;
    const member = parsed.member;
    if (!group) throw new Error('missing --group');
    if (!member) throw new Error('missing --member');
    if (!isValidId(group)) throw new Error(`invalid group id: ${group}`);
    if (!isValidId(member)) throw new Error(`invalid member id: ${member}`);

    const store = loadStore(storePath);
    if (!store.groups[group]) {
      throw new Error(`group does not exist: ${group}`);
    }

    // Optional check: member must be an existing principal or group
    const isPrincipal = store.principals.includes(member);
    const isGroup = !!store.groups[member];
    if (!isPrincipal && !isGroup) {
      throw new Error(`member does not exist as principal or group: ${member}`);
    }

    // Check if adding creates circular reference
    // If member is a group, group cannot be added as a member if group is an ancestor of member
    if (member === group) {
      throw new Error('group cannot be a member of itself');
    }
    if (isGroup) {
      // Check if group is reachable from member via membership
      const membersOfMember = getAllSubMembers(store, member);
      if (membersOfMember.has(group)) {
        throw new Error('circular group membership detected');
      }
    }

    if (store.groups[group].includes(member)) {
      throw new Error(`member already in group: ${member}`);
    }

    store.groups[group].push(member);
    saveStore(storePath, store);
    process.exit(0);
  } else if (action === 'list') {
    const store = loadStore(storePath);
    for (const g of Object.keys(store.groups).sort()) {
      console.log(g);
    }
    process.exit(0);
  } else {
    throw new Error(`unknown group action: ${action}`);
  }
}

function getAllSubMembers(store, rootId) {
  const visited = new Set();
  const queue = [rootId];
  while (queue.length > 0) {
    const curr = queue.shift();
    if (visited.has(curr)) continue;
    visited.add(curr);
    if (store.groups[curr]) {
      for (const m of store.groups[curr]) {
        queue.push(m);
      }
    }
  }
  return visited;
}

// ----------------------------------------------------
// RESOURCE
// ----------------------------------------------------
function handleResource(storePath, args) {
  const parsed = parseArgs(args);
  const action = parsed._args[0];

  if (action === 'add') {
    // Resources in grantline are hierarchical paths. 
    // Are resources stored explicitly as a list, or just implied by rules/paths?
    // Let's check specification: 
    // "Resources are hierarchical paths (/finance/reports/q3)..."
    // Does the CLI have `resource add`? Let's verify if `resource add` is requested or if resources are implicit or explicit.
    // Wait, let's check what commands are standard or if `resource add` is needed.
    // Let's support `resource add --path <path>` just in case, or list them if stored. 
    // Wait, let's check if resources need explicit storage or if they are just validated.
    // Let's store resources explicitly in the store JSON object as `resources: []` if `resource add` is called, 
    // or validate resource paths. Let's add `resources` array to store structure.
    const pathArg = parsed.path;
    if (!pathArg) throw new Error('missing --path');
    if (!isValidResourcePath(pathArg)) throw new Error(`invalid resource path: ${pathArg}`);

    const store = loadStore(storePath);
    if (!store.resources) store.resources = [];
    if (store.resources.includes(pathArg)) {
      throw new Error(`resource already exists: ${pathArg}`);
    }
    store.resources.push(pathArg);
    saveStore(storePath, store);
    process.exit(0);
  } else if (action === 'list') {
    const store = loadStore(storePath);
    const resList = store.resources || [];
    for (const r of resList.sort()) {
      console.log(r);
    }
    process.exit(0);
  } else {
    throw new Error(`unknown resource action: ${action}`);
  }
}

// ----------------------------------------------------
// RULE
// ----------------------------------------------------
function handleRule(storePath, args) {
  const parsed = parseArgs(args);
  const action = parsed._args[0];

  if (action === 'add') {
    const target = parsed.target;
    const ruleAction = parsed.action;
    const resource = parsed.resource;
    const effect = parsed.effect;
    const validFrom = parsed.valid_from;
    const validUntil = parsed.valid_until;

    if (!target) throw new Error('missing --target');
    if (!ruleAction) throw new Error('missing --action');
    if (!resource) throw new Error('missing --resource');
    if (!effect) throw new Error('missing --effect');

    if (!isValidId(target)) throw new Error(`invalid target id: ${target}`);
    if (!['read', 'write', 'admin'].includes(ruleAction)) throw new Error(`invalid action: ${ruleAction}`);
    if (!isValidResourcePath(resource)) throw new Error(`invalid resource path: ${resource}`);
    if (!['allow', 'deny'].includes(effect)) throw new Error(`invalid effect: ${effect}`);

    if (validFrom !== undefined && Number.isNaN(Date.parse(validFrom))) {
      throw new Error(`invalid valid_from timestamp: ${validFrom}`);
    }
    if (validUntil !== undefined && Number.isNaN(Date.parse(validUntil))) {
      throw new Error(`invalid valid_until timestamp: ${validUntil}`);
    }

    const store = loadStore(storePath);

    // Verify target exists as principal or group
    const isPrincipal = store.principals.includes(target);
    const isGroup = !!store.groups[target];
    if (!isPrincipal && !isGroup) {
      throw new Error(`target does not exist as principal or group: ${target}`);
    }

    const newRule = {
      target,
      action: ruleAction,
      resource,
      effect
    };
    if (validFrom) newRule.valid_from = validFrom;
    if (validUntil) newRule.valid_until = validUntil;

    store.rules.push(newRule);
    saveStore(storePath, store);
    process.exit(0);
  } else if (action === 'list') {
    const store = loadStore(storePath);
    store.rules.forEach((r, idx) => {
      let line = `[${idx}] target=${r.target} action=${r.action} resource=${r.resource} effect=${r.effect}`;
      if (r.valid_from) line += ` valid_from=${r.valid_from}`;
      if (r.valid_until) line += ` valid_until=${r.valid_until}`;
      console.log(line);
    });
    process.exit(0);
  } else {
    throw new Error(`unknown rule action: ${action}`);
  }
}

// ----------------------------------------------------
// QUERY
// ----------------------------------------------------
function handleQuery(storePath, args) {
  const parsed = parseArgs(args);
  const principal = parsed.principal;
  const action = parsed.action;
  const resource = parsed.resource;
  const at = parsed.at;

  if (!principal) throw new Error('missing --principal');
  if (!action) throw new Error('missing --action');
  if (!resource) throw new Error('missing --resource');

  if (!isValidId(principal)) throw new Error(`invalid principal id: ${principal}`);
  if (!['read', 'write', 'admin'].includes(action)) throw new Error(`invalid action: ${action}`);
  if (!isValidResourcePath(resource)) throw new Error(`invalid resource path: ${resource}`);

  const store = loadStore(storePath);
  
  // Verify principal exists
  if (!store.principals.includes(principal)) {
    throw new Error(`principal does not exist: ${principal}`);
  }

  const { result } = evaluateQuery(store, principal, action, resource, at);
  console.log(result);
  process.exit(0);
}

// ----------------------------------------------------
// EXPLAIN
// ----------------------------------------------------
function handleExplain(storePath, args) {
  const parsed = parseArgs(args);
  const principal = parsed.principal;
  const action = parsed.action;
  const resource = parsed.resource;
  const at = parsed.at;

  if (!principal) throw new Error('missing --principal');
  if (!action) throw new Error('missing --action');
  if (!resource) throw new Error('missing --resource');

  if (!isValidId(principal)) throw new Error(`invalid principal id: ${principal}`);
  if (!['read', 'write', 'admin'].includes(action)) throw new Error(`invalid action: ${action}`);
  if (!isValidResourcePath(resource)) throw new Error(`invalid resource path: ${resource}`);

  const store = loadStore(storePath);

  if (!store.principals.includes(principal)) {
    throw new Error(`principal does not exist: ${principal}`);
  }

  const { result, matchingRules } = evaluateQuery(store, principal, action, resource, at);
  
  console.log(`Result: ${result}`);
  console.log(`Principal: ${principal}`);
  console.log(`Action: ${action}`);
  console.log(`Resource: ${resource}`);
  if (at) console.log(`Evaluation Time (T): ${at}`);
  
  console.log(`Matching rules (${matchingRules.length}):`);
  matchingRules.forEach((r, idx) => {
    let line = `  ${idx + 1}. target=${r.target} action=${r.action} resource=${r.resource} effect=${r.effect}`;
    if (r.valid_from) line += ` valid_from=${r.valid_from}`;
    if (r.valid_until) line += ` valid_until=${r.valid_until}`;
    console.log(line);
  });

  process.exit(0);
}
===END FILE===

===FILE: test/grantline.test.js===
import { strict as assert } from 'assert';
import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';

const CLI_PATH = path.resolve('bin/grantline.js');
const TEST_STORE = path.resolve('test-grantline.store');

function runCli(args, input = '') {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    input,
    encoding: 'utf8'
  });
  return {
    status: res.status,
    stdout: res.stdout.trim(),
    stderr: res.stderr.trim()
  };
}

// Cleanup before and after tests
try { if (fs.existsSync(TEST_STORE)) fs.unlinkSync(TEST_STORE); } catch {}

console.log('Running Grantline authorization CLI tests...');

// 1. Add principal
let r = runCli(['--store', TEST_STORE, 'principal', 'add', '--id', 'alice']);
assert.equal(r.status, 0);

// 2. Add duplicate principal fails
r = runCli(['--store', TEST_STORE, 'principal', 'add', '--id', 'alice']);
assert.notEqual(r.status, 0);

// 3. Add group and member
r = runCli(['--store', TEST_STORE, 'group', 'add', '--id', 'team']);
assert.equal(r.status, 0);

r = runCli(['--store', TEST_STORE, 'group', 'add-member', '--group', 'team', '--member', 'alice']);
assert.equal(r.status, 0);

// 4. Add resource
r = runCli(['--store', TEST_STORE, 'resource', 'add', '--path', '/app']);
assert.equal(r.status, 0);
r = runCli(['--store', TEST_STORE, 'resource', 'add', '--path', '/app/secrets']);
assert.equal(r.status, 0);

// 5. Add rule (deny on /app for team)
r = runCli(['--store', TEST_STORE, 'rule', 'add', '--target', 'team', '--action', 'read', '--resource', '/app', '--effect', 'deny']);
assert.equal(r.status, 0);

// 6. Add rule (allow on /app/secrets for team)
r = runCli(['--store', TEST_STORE, 'rule', 'add', '--target', 'team', '--action', 'read', '--resource', '/app/secrets', '--effect', 'allow']);
assert.equal(r.status, 0);

// 7. Query alice reads /app/secrets/key -> ALLOW (deeper allow beats broader deny)
r = runCli(['--store', TEST_STORE, 'query', '--principal', 'alice', '--action', 'read', '--resource', '/app/secrets/key']);
assert.equal(r.status, 0);
assert.equal(r.stdout, 'ALLOW');

// 8. Query alice reads /app/other -> DENY
r = runCli(['--store', TEST_STORE, 'query', '--principal', 'alice', '--action', 'read', '--resource', '/app/other']);
assert.equal(r.status, 0);
assert.equal(r.stdout, 'DENY');

// 9. Time bounded rule test
r = runCli(['--store', TEST_STORE, 'resource', 'add', '--path', '/a']);
r = runCli(['--store', TEST_STORE, 'rule', 'add', '--target', 'alice', '--action', 'read', '--resource', '/a', '--effect', 'allow', '--valid_until', '2025-06-01T00:00:00Z']);

// At 2025-06-01T00:00:00Z -> DENY (strictly before)
r = runCli(['--store', TEST_STORE, 'query', '--principal', 'alice', '--action', 'read', '--resource', '/a/x', '--at', '2025-06-01T00:00:00Z']);
assert.equal(r.status, 0);
assert.equal(r.stdout, 'DENY');

// At 2025-05-31T23:59:59Z -> ALLOW
r = runCli(['--store', TEST_STORE, 'query', '--principal', 'alice', '--action', 'read', '--resource', '/a/x', '--at', '2025-05-31T23:59:59Z']);
assert.equal(r.status, 0);
assert.equal(r.stdout, 'ALLOW');

// Cleanup test store
try { if (fs.existsSync(TEST_STORE)) fs.unlinkSync(TEST_STORE); } catch {}

console.log('All tests passed successfully!');
===END FILE===
```
