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
