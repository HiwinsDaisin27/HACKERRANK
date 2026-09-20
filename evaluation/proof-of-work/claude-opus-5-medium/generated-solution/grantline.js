#!/usr/bin/env node
'use strict';

/*
 * grantline — authorization CLI
 *
 * Loads a JSON store from disk, performs exactly one operation, writes outputs,
 * and (for successful mutations) updates the store atomically. Exits with:
 *   0  success
 *   1  general failure (message on stderr: "grantline: <msg>")
 *   3  store corruption    ("grantline: store corruption detected: <reason>")
 */

const fs = require('fs');
const path = require('path');

/* ------------------------------------------------------------------ */
/* constants                                                          */
/* ------------------------------------------------------------------ */

const ID_RE = /^[A-Za-z0-9._-]+$/;
const ACTIONS = new Set(['read', 'write', 'admin']);
const EFFECTS = new Set(['allow', 'deny']);

/* ------------------------------------------------------------------ */
/* errors                                                             */
/* ------------------------------------------------------------------ */

function fail(msg) {
  process.stderr.write(`grantline: ${msg}\n`);
  process.exit(1);
}

function corruption(reason) {
  process.stderr.write(`grantline: store corruption detected: ${reason}\n`);
  process.exit(3);
}

/* ------------------------------------------------------------------ */
/* validation helpers                                                 */
/* ------------------------------------------------------------------ */

function validId(id) {
  return typeof id === 'string' && id.length > 0 && ID_RE.test(id);
}

function validPath(p) {
  if (typeof p !== 'string' || p.length === 0) return false;
  if (p === '/') return true;
  if (p[0] !== '/') return false;
  if (p[p.length - 1] === '/') return false;
  const segs = p.split('/');
  for (let i = 1; i < segs.length; i++) {
    if (segs[i] === '') return false;
  }
  return true;
}

function pathDepth(p) {
  // Per spec: "/" is treated as a single-segment path (broadest).
  if (p === '/') return 1;
  return p.split('/').length - 1;
}

function pathMatches(rulePath, reqPath) {
  if (rulePath === reqPath) return true;
  if (rulePath === '/') return true;
  return reqPath.startsWith(rulePath + '/');
}

function parseIsoTs(s) {
  if (typeof s !== 'string' || s.length === 0) return NaN;
  return Date.parse(s);
}

/* ------------------------------------------------------------------ */
/* store                                                              */
/* ------------------------------------------------------------------ */

function emptyStore() {
  return {
    nextRuleId: 1,
    principals: [],
    groups: {},
    resources: [],
    rules: []
  };
}

function validateStore(s) {
  if (!s || typeof s !== 'object' || Array.isArray(s)) {
    corruption('store root must be an object');
  }
  if (!Array.isArray(s.principals)) corruption('principals must be an array');
  if (!s.groups || typeof s.groups !== 'object' || Array.isArray(s.groups)) {
    corruption('groups must be an object');
  }
  if (!Array.isArray(s.resources)) corruption('resources must be an array');
  if (!Array.isArray(s.rules)) corruption('rules must be an array');
  if (s.nextRuleId !== undefined &&
      (typeof s.nextRuleId !== 'number' || !Number.isFinite(s.nextRuleId))) {
    corruption('nextRuleId must be a number');
  }

  /* principals */
  const principals = new Set();
  for (const p of s.principals) {
    if (!validId(p)) corruption(`invalid principal id: ${p}`);
    if (principals.has(p)) corruption(`duplicate principal: ${p}`);
    principals.add(p);
  }

  /* groups */
  const groups = new Set(Object.keys(s.groups));
  for (const g of groups) {
    if (!validId(g)) corruption(`invalid group id: ${g}`);
  }

  for (const g of groups) {
    const grp = s.groups[g];
    if (!grp || typeof grp !== 'object' || Array.isArray(grp)) {
      corruption(`invalid group record: ${g}`);
    }
    if (!Array.isArray(grp.members)) {
      corruption(`group ${g} members must be an array`);
    }
    const seen = new Set();
    for (const m of grp.members) {
      if (!validId(m)) corruption(`invalid member id in group ${g}: ${m}`);
      if (seen.has(m)) corruption(`duplicate member ${m} in group ${g}`);
      seen.add(m);
      if (!principals.has(m) && !groups.has(m)) {
        corruption(`group ${g} references unknown member ${m}`);
      }
    }
  }

  /* cycle detection on group nesting */
  const parentsOf = new Map();
  for (const g of groups) {
    for (const m of s.groups[g].members) {
      if (!parentsOf.has(m)) parentsOf.set(m, []);
      parentsOf.get(m).push(g);
    }
  }
  const visited = new Set();
  const stack = new Set();
  function dfs(node) {
    if (stack.has(node)) return true;
    if (visited.has(node)) return false;
    visited.add(node);
    stack.add(node);
    for (const p of (parentsOf.get(node) || [])) {
      if (dfs(p)) return true;
    }
    stack.delete(node);
    return false;
  }
  for (const g of groups) {
    if (dfs(g)) corruption('group nesting cycle detected');
  }

  /* resources */
  const resources = new Set();
  for (const r of s.resources) {
    if (!validPath(r)) corruption(`invalid resource path: ${r}`);
    if (resources.has(r)) corruption(`duplicate resource: ${r}`);
    resources.add(r);
  }

  /* rules */
  const ruleIds = new Set();
  for (const rule of s.rules) {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      corruption('invalid rule record');
    }
    if (typeof rule.id !== 'number' || !Number.isFinite(rule.id)) {
      corruption('invalid rule id');
    }
    if (ruleIds.has(rule.id)) corruption(`duplicate rule id: ${rule.id}`);
    ruleIds.add(rule.id);
    if (!validId(rule.target)) corruption(`invalid rule target: ${rule.target}`);
    if (!principals.has(rule.target) && !groups.has(rule.target)) {
      corruption(`rule target unknown: ${rule.target}`);
    }
    if (!ACTIONS.has(rule.action)) corruption(`invalid rule action: ${rule.action}`);
    if (!validPath(rule.resource)) corruption(`invalid rule resource: ${rule.resource}`);
    if (!EFFECTS.has(rule.effect)) corruption(`invalid rule effect: ${rule.effect}`);
    if (rule.valid_from != null) {
      if (typeof rule.valid_from !== 'string' || isNaN(parseIsoTs(rule.valid_from))) {
        corruption(`invalid valid_from on rule ${rule.id}`);
      }
    }
    if (rule.valid_until != null) {
      if (typeof rule.valid_until !== 'string' || isNaN(parseIsoTs(rule.valid_until))) {
        corruption(`invalid valid_until on rule ${rule.id}`);
      }
    }
  }
}

function loadStore(storePath) {
  let raw;
  try {
    raw = fs.readFileSync(storePath, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return emptyStore();
    fail(`cannot read store: ${e.message}`);
  }
  if (raw.trim() === '') return emptyStore();
  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    corruption(`invalid JSON: ${e.message}`);
  }
  validateStore(data);
  if (typeof data.nextRuleId !== 'number') data.nextRuleId = 1;
  return data;
}

function saveStore(storePath, store) {
  const dir = path.dirname(path.resolve(storePath));
  try { fs.mkdirSync(dir, { recursive: true }); } catch (_) { /* ignore */ }
  const data = JSON.stringify(store, null, 2) + '\n';
  const tmp = `${storePath}.tmp.${process.pid}.${Date.now()}`;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, storePath);
}

/* ------------------------------------------------------------------ */
/* evaluation                                                         */
/* ------------------------------------------------------------------ */

function principalGroups(store, principal) {
  const parentsOf = new Map();
  for (const [g, obj] of Object.entries(store.groups)) {
    for (const m of obj.members) {
      if (!parentsOf.has(m)) parentsOf.set(m, []);
      parentsOf.get(m).push(g);
    }
  }
  const result = new Set();
  const queue = [principal];
  while (queue.length) {
    const cur = queue.shift();
    const parents = parentsOf.get(cur) || [];
    for (const p of parents) {
      if (!result.has(p)) {
        result.add(p);
        queue.push(p);
      }
    }
  }
  return result;
}

function evaluate(store, principal, action, resource, T) {
  const groups = principalGroups(store, principal);
  const applicable = [];
  for (const rule of store.rules) {
    if (rule.action !== action) continue;
    if (rule.target !== principal && !groups.has(rule.target)) continue;
    if (!pathMatches(rule.resource, resource)) continue;
    const from = rule.valid_from != null ? Date.parse(rule.valid_from) : -Infinity;
    const until = rule.valid_until != null ? Date.parse(rule.valid_until) : Infinity;
    if (!(T >= from)) continue;
    if (!(T < until)) continue;
    applicable.push({ rule, depth: pathDepth(rule.resource) });
  }

  if (applicable.length === 0) {
    return { decision: 'DENY', applicable: [], winning: [], maxDepth: null };
  }

  let maxDepth = -Infinity;
  for (const a of applicable) if (a.depth > maxDepth) maxDepth = a.depth;
  const top = applicable.filter(a => a.depth === maxDepth);
  const hasDeny = top.some(a => a.rule.effect === 'deny');

  return {
    decision: hasDeny ? 'DENY' : 'ALLOW',
    applicable,
    winning: top,
    maxDepth
  };
}

/* ------------------------------------------------------------------ */
/* CLI parsing                                                        */
/* ------------------------------------------------------------------ */

function parseArgs(argv) {
  const opts = { store: null, at: null, validFrom: null, validUntil: null };
  const pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--store') {
      if (++i >= argv.length) fail('--store requires a value');
      opts.store = argv[i];
    } else if (a.startsWith('--store=')) {
      opts.store = a.slice(8);
    } else if (a === '--at') {
      if (++i >= argv.length) fail('--at requires a value');
      opts.at = argv[i];
    } else if (a.startsWith('--at=')) {
      opts.at = a.slice(5);
    } else if (a === '--valid-from') {
      if (++i >= argv.length) fail('--valid-from requires a value');
      opts.validFrom = argv[i];
    } else if (a.startsWith('--valid-from=')) {
      opts.validFrom = a.slice(13);
    } else if (a === '--valid-until') {
      if (++i >= argv.length) fail('--valid-until requires a value');
      opts.validUntil = argv[i];
    } else if (a.startsWith('--valid-until=')) {
      opts.validUntil = a.slice(14);
    } else if (a.startsWith('--')) {
      fail(`unknown option: ${a}`);
    } else {
      pos.push(a);
    }
  }
  return { opts, pos };
}

/* ------------------------------------------------------------------ */
/* commands                                                           */
/* ------------------------------------------------------------------ */

function cmdPrincipal(opts, args) {
  if (args.length < 1) fail('usage: principal <create|delete|list> [id]');
  const sub = args[0];
  const store = loadStore(opts.store);

  if (sub === 'create') {
    if (args.length < 2) fail('usage: principal create <id>');
    const id = args[1];
    if (!validId(id)) fail(`invalid principal id: ${id}`);
    if (store.principals.includes(id)) fail(`principal already exists: ${id}`);
    store.principals.push(id);
    saveStore(opts.store, store);
    return;
  }

  if (sub === 'delete') {
    if (args.length < 2) fail('usage: principal delete <id>');
    const id = args[1];
    if (!store.principals.includes(id)) fail(`principal not found: ${id}`);
    for (const [g, obj] of Object.entries(store.groups)) {
      if (obj.members.includes(id)) fail(`principal is a member of group: ${g}`);
    }
    for (const r of store.rules) {
      if (r.target === id) fail(`principal is targeted by rule: ${r.id}`);
    }
    store.principals = store.principals.filter(p => p !== id);
    saveStore(opts.store, store);
    return;
  }

  if (sub === 'list') {
    for (const p of store.principals) process.stdout.write(p + '\n');
    return;
  }

  fail(`unknown principal subcommand: ${sub}`);
}

function wouldCreateCycle(store, groupId, memberId) {
  if (groupId === memberId) return true;
  if (!store.groups[memberId]) return false; // member is a principal
  const visited = new Set();
  const queue = [memberId];
  while (queue.length) {
    const cur = queue.shift();
    if (cur === groupId) return true;
    if (visited.has(cur)) continue;
    visited.add(cur);
    const grp = store.groups[cur];
    if (!grp) continue;
    for (const child of grp.members) {
      if (store.groups[child]) queue.push(child);
    }
  }
  return false;
}

function cmdGroup(opts, args) {
  if (args.length < 1) fail('usage: group <create|delete|add-member|remove-member|list> ...');
  const sub = args[0];
  const store = loadStore(opts.store);

  if (sub === 'create') {
    if (args.length < 2) fail('usage: group create <id>');
    const id = args[1];
    if (!validId(id)) fail(`invalid group id: ${id}`);
    if (store.groups[id]) fail(`group already exists: ${id}`);
    store.groups[id] = { members: [] };
    saveStore(opts.store, store);
    return;
  }

  if (sub === 'delete') {
    if (args.length < 2) fail('usage: group delete <id>');
    const id = args[1];
    if (!store.groups[id]) fail(`group not found: ${id}`);
    for (const [g, obj] of Object.entries(store.groups)) {
      if (g !== id && obj.members.includes(id)) fail(`group is a member of: ${g}`);
    }
    for (const r of store.rules) {
      if (r.target === id) fail(`group is targeted by rule: ${r.id}`);
    }
    delete store.groups[id];
    saveStore(opts.store, store);
    return;
  }

  if (sub === 'add-member') {
    if (args.length < 3) fail('usage: group add-member <group> <member>');
    const g = args[1], m = args[2];
    if (!validId(g)) fail(`invalid group id: ${g}`);
    if (!validId(m)) fail(`invalid member id: ${m}`);
    if (!store.groups[g]) fail(`group not found: ${g}`);
    if (!store.principals.includes(m) && !store.groups[m]) fail(`member not found: ${m}`);
    if (store.groups[g].members.includes(m)) fail(`member already present: ${m}`);
    if (wouldCreateCycle(store, g, m)) fail('operation would create a group nesting cycle');
    store.groups[g].members.push(m);
    saveStore(opts.store, store);
    return;
  }

  if (sub === 'remove-member') {
    if (args.length < 3) fail('usage: group remove-member <group> <member>');
    const g = args[1], m = args[2];
    if (!store.groups[g]) fail(`group not found: ${g}`);
    if (!store.groups[g].members.includes(m)) fail(`member not present: ${m}`);
    store.groups[g].members = store.groups[g].members.filter(x => x !== m);
    saveStore(opts.store, store);
    return;
  }

  if (sub === 'list') {
    for (const g of Object.keys(store.groups)) process.stdout.write(g + '\n');
    return;
  }

  fail(`unknown group subcommand: ${sub}`);
}

function cmdResource(opts, args) {
  if (args.length < 1) fail('usage: resource <create|delete|list> [path]');
  const sub = args[0];
  const store = loadStore(opts.store);

  if (sub === 'create') {
    if (args.length < 2) fail('usage: resource create <path>');
    const p = args[1];
    if (!validPath(p)) fail(`invalid resource path: ${p}`);
    if (store.resources.includes(p)) fail(`resource already exists: ${p}`);
    store.resources.push(p);
    saveStore(opts.store, store);
    return;
  }

  if (sub === 'delete') {
    if (args.length < 2) fail('usage: resource delete <path>');
    const p = args[1];
    if (!store.resources.includes(p)) fail(`resource not found: ${p}`);
    for (const r of store.rules) {
      if (r.resource === p) fail(`resource is referenced by rule: ${r.id}`);
    }
    store.resources = store.resources.filter(x => x !== p);
    saveStore(opts.store, store);
    return;
  }

  if (sub === 'list') {
    for (const p of store.resources) process.stdout.write(p + '\n');
    return;
  }

  fail(`unknown resource subcommand: ${sub}`);
}

function cmdRule(opts, args) {
  if (args.length < 1) fail('usage: rule <add|remove|list> ...');
  const sub = args[0];
  const store = loadStore(opts.store);

  if (sub === 'add') {
    // rule add <target> <action> <resource> <effect> [--valid-from T] [--valid-until T]
    if (args.length < 5) {
      fail('usage: rule add <target> <action> <resource> <effect> [--valid-from T] [--valid-until T]');
    }
    const target = args[1];
    const action = args[2];
    const resource = args[3];
    const effect = args[4];

    if (!validId(target)) fail(`invalid target id: ${target}`);
    if (!store.principals.includes(target) && !store.groups[target]) {
      fail(`target not found: ${target}`);
    }
    if (!ACTIONS.has(action)) fail(`invalid action: ${action}`);
    if (!validPath(resource)) fail(`invalid resource path: ${resource}`);
    if (!EFFECTS.has(effect)) fail(`invalid effect: ${effect}`);

    let validFrom = null;
    let validUntil = null;
    if (opts.validFrom != null) {
      if (isNaN(parseIsoTs(opts.validFrom))) fail(`invalid --valid-from: ${opts.validFrom}`);
      validFrom = opts.validFrom;
    }
    if (opts.validUntil != null) {
      if (isNaN(parseIsoTs(opts.validUntil))) fail(`invalid --valid-until: ${opts.validUntil}`);
      validUntil = opts.validUntil;
    }
    if (validFrom != null && validUntil != null) {
      if (Date.parse(validFrom) > Date.parse(validUntil)) {
        fail('--valid-from must not be after --valid-until');
      }
    }

    const id = store.nextRuleId || 1;
    store.nextRuleId = id + 1;
    store.rules.push({
      id,
      target,
      action,
      resource,
      effect,
      valid_from: validFrom,
      valid_until: validUntil
    });
    if (!store.resources.includes(resource)) store.resources.push(resource);
    saveStore(opts.store, store);
    process.stdout.write(String(id) + '\n');
    return;
  }

  if (sub === 'remove') {
    if (args.length < 2) fail('usage: rule remove <id>');
    const id = Number(args[1]);
    if (!Number.isInteger(id)) fail(`invalid rule id: ${args[1]}`);
    const idx = store.rules.findIndex(r => r.id === id);
    if (idx < 0) fail(`rule not found: ${id}`);
    store.rules.splice(idx, 1);
    saveStore(opts.store, store);
    return;
  }

  if (sub === 'list') {
    for (const r of store.rules) process.stdout.write(JSON.stringify(r) + '\n');
    return;
  }

  fail(`unknown rule subcommand: ${sub}`);
}

function resolveAt(opts) {
  if (opts.at == null) return Date.now();
  const t = parseIsoTs(opts.at);
  if (isNaN(t)) fail(`invalid --at: ${opts.at}`);
  return t;
}

function cmdQuery(opts, args) {
  if (args.length < 3) {
    fail('usage: query <principal> <action> <resource> [--at T]');
  }
  const principal = args[0];
  const action = args[1];
  const resource = args[2];

  if (!validId(principal)) fail(`invalid principal: ${principal}`);
  if (!ACTIONS.has(action)) fail(`invalid action: ${action}`);
  if (!validPath(resource)) fail(`invalid resource path: ${resource}`);

  const T = resolveAt(opts);
  const store = loadStore(opts.store);

  if (!store.principals.includes(principal)) {
    process.stdout.write('DENY\n');
    return;
  }

  const res = evaluate(store, principal, action, resource, T);
  process.stdout.write(res.decision + '\n');
}

function cmdExplain(opts, args) {
  if (args.length < 3) {
    fail('usage: explain <principal> <action> <resource> [--at T]');
  }
  const principal = args[0];
  const action = args[1];
  const resource = args[2];

  if (!validId(principal)) fail(`invalid principal: ${principal}`);
  if (!ACTIONS.has(action)) fail(`invalid action: ${action}`);
  if (!validPath(resource)) fail(`invalid resource path: ${resource}`);

  const T = resolveAt(opts);
  const store = loadStore(opts.store);

  if (!store.principals.includes(principal)) {
    const out = {
      decision: 'DENY',
      principal,
      action,
      resource,
      at: new Date(T).toISOString(),
      reason: 'principal not found',
      applicable: [],
      winning: []
    };
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    return;
  }

  const res = evaluate(store, principal, action, resource, T);
  const winnerIds = new Set(res.winning.map(w => w.rule.id));
  const out = {
    decision: res.decision,
    principal,
    action,
    resource,
    at: new Date(T).toISOString(),
    applicable: res.applicable.map(a => ({
      id: a.rule.id,
      effect: a.rule.effect,
      target: a.rule.target,
      action: a.rule.action,
      resource: a.rule.resource,
      valid_from: a.rule.valid_from,
      valid_until: a.rule.valid_until,
      depth: a.depth,
      winner: winnerIds.has(a.rule.id)
    })),
    winning: res.winning.map(w => w.rule.id)
  };
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
}

/* ------------------------------------------------------------------ */
/* entry                                                              */
/* ------------------------------------------------------------------ */

function main(argv) {
  const { opts, pos } = parseArgs(argv);

  if (pos.length === 0) {
    fail('no command provided; try: principal | group | resource | rule | query | explain');
  }
  if (!opts.store) fail('missing required --store <path>');

  const cmd = pos[0];
  const rest = pos.slice(1);

  switch (cmd) {
    case 'principal': return cmdPrincipal(opts, rest);
    case 'group':     return cmdGroup(opts, rest);
    case 'resource':  return cmdResource(opts, rest);
    case 'rule':      return cmdRule(opts, rest);
    case 'query':     return cmdQuery(opts, rest);
    case 'explain':   return cmdExplain(opts, rest);
    default:          fail(`unknown command: ${cmd}`);
  }
}

main(process.argv.slice(2));
