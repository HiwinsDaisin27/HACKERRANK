'use strict';
const fs = require('fs');
const path = require('path');

class CorruptError extends Error {}
class UsageError extends Error {}

const ID_RE = /^[A-Za-z0-9._-]+$/;
const ACTIONS = ['read', 'write', 'admin'];
const EFFECTS = ['allow', 'deny'];

// ---------------------------------------------------------------- helpers

function isValidId(s) {
  return typeof s === 'string' && ID_RE.test(s);
}

function isValidPath(p) {
  if (typeof p !== 'string' || p[0] !== '/') return false;
  if (p === '/') return true;
  if (p.endsWith('/')) return false;
  return p.slice(1).split('/').every((seg) => seg.length > 0);
}

function segCount(p) {
  return p === '/' ? 1 : p.split('/').length - 1;
}

function pathCovers(rulePath, reqPath) {
  if (rulePath === '/') return true;
  return reqPath === rulePath || reqPath.startsWith(rulePath + '/');
}

const TS_RE = /^(\d{4})-(\d{2})-(\d{2})(?:[Tt](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?(Z|z|[+-]\d{2}:?\d{2})?)?$/;

// Returns epoch milliseconds or null when invalid.
function parseTimestamp(s) {
  if (typeof s !== 'string') return null;
  const m = TS_RE.exec(s);
  if (!m) return null;
  const y = +m[1], mo = +m[2], d = +m[3];
  const h = m[4] === undefined ? 0 : +m[4];
  const mi = m[5] === undefined ? 0 : +m[5];
  const sec = m[6] === undefined ? 0 : +m[6];
  if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || sec > 59) return null;
  let ms = 0;
  if (m[7] !== undefined) ms = Math.floor(Number('0.' + m[7]) * 1000);
  const base = new Date(0);
  base.setUTCFullYear(y, mo - 1, d);
  base.setUTCHours(h, mi, sec, ms);
  if (base.getUTCFullYear() !== y || base.getUTCMonth() !== mo - 1 || base.getUTCDate() !== d) return null;
  let t = base.getTime();
  const z = m[8];
  if (z && z !== 'Z' && z !== 'z') {
    const sign = z[0] === '-' ? -1 : 1;
    const digits = z.slice(1).replace(':', '');
    const oh = +digits.slice(0, 2), om = +digits.slice(2, 4);
    if (oh > 23 || om > 59) return null;
    t -= sign * (oh * 60 + om) * 60000;
  }
  return Number.isFinite(t) ? t : null;
}

function cmpStr(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// ---------------------------------------------------------------- args

const SPECS = {
  'init': { req: ['store'], opt: [] },
  'add-principal': { req: ['store', 'id'], opt: [] },
  'add-group': { req: ['store', 'id'], opt: [] },
  'add-group-member': { req: ['store', 'group', 'member'], opt: [] },
  'remove-group-member': { req: ['store', 'group', 'member'], opt: [] },
  'grant': { req: ['store', 'principal-or-group', 'resource', 'action'], opt: ['valid-from', 'valid-until'] },
  'deny': { req: ['store', 'principal-or-group', 'resource', 'action'], opt: ['valid-from', 'valid-until'] },
  'revoke': { req: ['store', 'rule-id'], opt: [] },
  'query': { req: ['store', 'principal', 'resource', 'action'], opt: ['at'] },
  'explain': { req: ['store', 'principal', 'resource', 'action'], opt: ['at'] },
  'move-resource': { req: ['store', 'from', 'to'], opt: [] },
};

function parseArgs(argv) {
  if (argv.length === 0) throw new UsageError('missing command');
  const cmd = argv[0];
  const spec = SPECS[cmd];
  if (!spec) throw new UsageError(`unknown command: ${cmd}`);
  const args = {};
  for (let i = 1; i < argv.length; i++) {
    const tok = argv[i];
    if (!tok.startsWith('--')) throw new UsageError(`unexpected argument: ${tok}`);
    let name = tok.slice(2);
    let value;
    const eq = name.indexOf('=');
    if (eq >= 0) {
      value = name.slice(eq + 1);
      name = name.slice(0, eq);
    }
    if (!spec.req.includes(name) && !spec.opt.includes(name)) {
      throw new UsageError(`unknown option for ${cmd}: --${name}`);
    }
    if (value === undefined) {
      if (i + 1 >= argv.length) throw new UsageError(`option --${name} requires a value`);
      value = argv[++i];
    }
    if (Object.prototype.hasOwnProperty.call(args, name)) throw new UsageError(`duplicate option: --${name}`);
    args[name] = value;
  }
  for (const r of spec.req) {
    if (!Object.prototype.hasOwnProperty.call(args, r)) throw new UsageError(`missing required option: --${r}`);
  }
  return { cmd, args };
}

// ---------------------------------------------------------------- store

function emptyStore() {
  return { version: 1, principals: [], groups: {}, rules: [], next_rule_id: 1 };
}

function isPlainObject(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}

function validateStore(raw) {
  const bad = (reason) => { throw new CorruptError(reason); };
  if (!isPlainObject(raw)) bad('root is not an object');
  if (!Array.isArray(raw.principals)) bad('principals is not an array');
  if (!isPlainObject(raw.groups)) bad('groups is not an object');
  if (!Array.isArray(raw.rules)) bad('rules is not an array');
  if (!Number.isInteger(raw.next_rule_id) || raw.next_rule_id < 1) bad('invalid next_rule_id');

  const principals = new Set();
  for (const p of raw.principals) {
    if (!isValidId(p)) bad('invalid principal id');
    if (principals.has(p)) bad(`duplicate principal: ${p}`);
    principals.add(p);
  }

  const groupIds = Object.keys(raw.groups);
  const groups = new Set(groupIds);
  for (const g of groupIds) {
    if (!isValidId(g)) bad(`invalid group id: ${g}`);
    if (principals.has(g)) bad(`id used as both principal and group: ${g}`);
    const members = raw.groups[g];
    if (!Array.isArray(members)) bad(`members of group ${g} is not an array`);
    const seen = new Set();
    for (const m of members) {
      if (typeof m !== 'string') bad(`invalid member in group ${g}`);
      if (seen.has(m)) bad(`duplicate member ${m} in group ${g}`);
      seen.add(m);
      if (!principals.has(m) && !groups.has(m)) bad(`dangling member ${m} in group ${g}`);
    }
  }

  // cycle detection (iterative colouring DFS over group->group edges)
  const state = {};
  for (const start of groupIds) {
    if (state[start]) continue;
    const stack = [[start, 0]];
    state[start] = 1;
    while (stack.length) {
      const top = stack[stack.length - 1];
      const members = raw.groups[top[0]];
      if (top[1] >= members.length) {
        state[top[0]] = 2;
        stack.pop();
        continue;
      }
      const m = members[top[1]++];
      if (!groups.has(m)) continue;
      if (state[m] === 1) bad(`group cycle detected involving ${m}`);
      if (!state[m]) {
        state[m] = 1;
        stack.push([m, 0]);
      }
    }
  }

  const ruleIds = new Set();
  for (const r of raw.rules) {
    if (!isPlainObject(r)) bad('rule is not an object');
    if (typeof r.id !== 'string' || r.id.length === 0 || /\s/.test(r.id)) bad('invalid rule id');
    if (ruleIds.has(r.id)) bad(`duplicate rule id: ${r.id}`);
    ruleIds.add(r.id);
    if (!EFFECTS.includes(r.effect)) bad(`rule ${r.id}: invalid effect`);
    if (!ACTIONS.includes(r.action)) bad(`rule ${r.id}: invalid action`);
    if (!isValidPath(r.resource)) bad(`rule ${r.id}: invalid resource path`);
    if (typeof r.target !== 'string' || (!principals.has(r.target) && !groups.has(r.target))) {
      bad(`rule ${r.id}: dangling target`);
    }
    for (const k of ['valid_from', 'valid_until']) {
      if (r[k] !== undefined && r[k] !== null && parseTimestamp(r[k]) === null) {
        bad(`rule ${r.id}: invalid ${k}`);
      }
    }
    if (r.valid_from != null && r.valid_until != null &&
        !(parseTimestamp(r.valid_from) < parseTimestamp(r.valid_until))) {
      bad(`rule ${r.id}: valid_from is not before valid_until`);
    }
    const m = /^r(\d+)$/.exec(r.id);
    if (m && Number(m[1]) >= raw.next_rule_id) bad(`rule ${r.id}: next_rule_id is stale`);
  }

  return {
    version: raw.version === undefined ? 1 : raw.version,
    principals: raw.principals.slice(),
    groups: JSON.parse(JSON.stringify(raw.groups)),
    rules: raw.rules.map((r) => ({
      id: r.id,
      effect: r.effect,
      target: r.target,
      resource: r.resource,
      action: r.action,
      valid_from: r.valid_from == null ? null : r.valid_from,
      valid_until: r.valid_until == null ? null : r.valid_until,
    })),
    next_rule_id: raw.next_rule_id,
  };
}

function loadStore(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') throw new UsageError(`store not found: ${file}`);
    throw new UsageError(`cannot read store: ${e.message}`);
  }
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new CorruptError('malformed JSON');
  }
  return validateStore(raw);
}

function saveStore(file, store) {
  const dir = path.dirname(path.resolve(file));
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  const data = JSON.stringify(store, null, 2) + '\n';
  try {
    fs.writeFileSync(tmp, data, { flag: 'wx' });
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (_) { /* ignore */ }
    throw new UsageError(`cannot write store: ${e.message}`);
  }
}

// ---------------------------------------------------------------- model ops

function idExists(store, id) {
  return store.principals.includes(id) || Object.prototype.hasOwnProperty.call(store.groups, id);
}

function isGroup(store, id) {
  return Object.prototype.hasOwnProperty.call(store.groups, id);
}

// Can to be reached from from following group->nested-group edges?
function groupReaches(store, from, to) {
  const seen = new Set();
  const stack = [from];
  while (stack.length) {
    const g = stack.pop();
    if (g === to) return true;
    if (seen.has(g)) continue;
    seen.add(g);
    for (const m of store.groups[g] || []) if (isGroup(store, m)) stack.push(m);
  }
  return false;
}

function groupsOf(store, principal) {
  const parents = {};
  for (const g of Object.keys(store.groups)) {
    for (const m of store.groups[g]) (parents[m] = parents[m] || []).push(g);
  }
  const seen = new Set();
  const queue = [principal];
  while (queue.length) {
    const cur = queue.shift();
    for (const g of parents[cur] || []) {
      if (!seen.has(g)) {
        seen.add(g);
        queue.push(g);
      }
    }
  }
  return seen;
}

function inEffect(rule, T) {
  if (rule.valid_from != null && T < parseTimestamp(rule.valid_from)) return false;
  if (rule.valid_until != null && T >= parseTimestamp(rule.valid_until)) return false;
  return true;
}

function evaluate(store, principal, resource, action, T) {
  const groups = groupsOf(store, principal);
  const applicable = store.rules.filter((r) =>
    r.action === action &&
    (r.target === principal || groups.has(r.target)) &&
    pathCovers(r.resource, resource) &&
    inEffect(r, T));
  if (applicable.length === 0) return { decision: 'DENY', matches: [] };
  let best = 0;
  for (const r of applicable) best = Math.max(best, segCount(r.resource));
  const top = applicable.filter((r) => segCount(r.resource) === best);
  const denies = top.filter((r) => r.effect === 'deny');
  if (denies.length > 0) return { decision: 'DENY', matches: denies };
  return { decision: 'ALLOW', matches: top };
}

function membershipPath(store, groupId, principal) {
  const chains = [];
  const dfs = (cur, chain) => {
    const members = store.groups[cur];
    if (members.includes(principal)) chains.push(chain.join('>'));
    for (const m of members) if (isGroup(store, m)) dfs(m, chain.concat(m));
  };
  dfs(groupId, [groupId]);
  chains.sort(cmpStr);
  return chains[0];
}

function requireAction(a) {
  if (!ACTIONS.includes(a)) throw new UsageError(`invalid action: ${a}`);
}

function requirePath(p, label) {
  if (!isValidPath(p)) throw new UsageError(`invalid resource path${label ? ' (' + label + ')' : ''}: ${p}`);
}

function evalInstant(args) {
  if (args.at === undefined) return Date.now();
  const t = parseTimestamp(args.at);
  if (t === null) throw new UsageError(`invalid timestamp: ${args.at}`);
  return t;
}

function addRule(store, effect, args) {
  const target = args['principal-or-group'];
  if (!idExists(store, target)) throw new UsageError(`unknown principal or group: ${target}`);
  requirePath(args.resource);
  requireAction(args.action);
  let from = null, until = null, fromMs = null, untilMs = null;
  if (args['valid-from'] !== undefined) {
    fromMs = parseTimestamp(args['valid-from']);
    if (fromMs === null) throw new UsageError(`invalid timestamp: ${args['valid-from']}`);
    from = args['valid-from'];
  }
  if (args['valid-until'] !== undefined) {
    untilMs = parseTimestamp(args['valid-until']);
    if (untilMs === null) throw new UsageError(`invalid timestamp: ${args['valid-until']}`);
    until = args['valid-until'];
  }
  if (fromMs !== null && untilMs !== null && !(fromMs < untilMs)) {
    throw new UsageError('valid-from must be earlier than valid-until');
  }
  const existing = new Set(store.rules.map((r) => r.id));
  let n = store.next_rule_id;
  let id = 'r' + String(n).padStart(6, '0');
  while (existing.has(id)) {
    n++;
    id = 'r' + String(n).padStart(6, '0');
  }
  store.next_rule_id = n + 1;
  store.rules.push({
    id, effect, target, resource: args.resource, action: args.action,
    valid_from: from, valid_until: until,
  });
  return id + '\n';
}

// ---------------------------------------------------------------- commands

// Each handler returns { out, mutated }
function run(cmd, args, store) {
  switch (cmd) {
    case 'add-principal': {
      if (!isValidId(args.id)) throw new UsageError(`invalid id: ${args.id}`);
      if (idExists(store, args.id)) throw new UsageError(`id already exists: ${args.id}`);
      store.principals.push(args.id);
      return { out: '', mutated: true };
    }
    case 'add-group': {
      if (!isValidId(args.id)) throw new UsageError(`invalid id: ${args.id}`);
      if (idExists(store, args.id)) throw new UsageError(`id already exists: ${args.id}`);
      store.groups[args.id] = [];
      return { out: '', mutated: true };
    }
    case 'add-group-member': {
      if (!isGroup(store, args.group)) throw new UsageError(`unknown group: ${args.group}`);
      if (!idExists(store, args.member)) throw new UsageError(`unknown member: ${args.member}`);
      if (store.groups[args.group].includes(args.member)) {
        throw new UsageError(`${args.member} is already a member of ${args.group}`);
      }
      if (isGroup(store, args.member) && groupReaches(store, args.member, args.group)) {
        throw new UsageError(`adding ${args.member} to ${args.group} would create a cycle`);
      }
      store.groups[args.group].push(args.member);
      return { out: '', mutated: true };
    }
    case 'remove-group-member': {
      if (!isGroup(store, args.group)) throw new UsageError(`unknown group: ${args.group}`);
      const idx = store.groups[args.group].indexOf(args.member);
      if (idx < 0) throw new UsageError(`${args.member} is not a direct member of ${args.group}`);
      store.groups[args.group].splice(idx, 1);
      return { out: '', mutated: true };
    }
    case 'grant':
      return { out: addRule(store, 'allow', args), mutated: true };
    case 'deny':
      return { out: addRule(store, 'deny', args), mutated: true };
    case 'revoke': {
      const idx = store.rules.findIndex((r) => r.id === args['rule-id']);
      if (idx < 0) throw new UsageError(`unknown rule id: ${args['rule-id']}`);
      store.rules.splice(idx, 1);
      return { out: '', mutated: true };
    }
    case 'query':
    case 'explain': {
      if (!store.principals.includes(args.principal)) throw new UsageError(`unknown principal: ${args.principal}`);
      requirePath(args.resource);
      requireAction(args.action);
      const T = evalInstant(args);
      const res = evaluate(store, args.principal, args.resource, args.action, T);
      if (cmd === 'query') return { out: res.decision + '\n', mutated: false };
      let out = `DECISION: ${res.decision}\n`;
      if (res.matches.length === 0) {
        out += 'MATCH: none\n';
      } else {
        const sorted = res.matches.slice().sort((x, y) => cmpStr(x.id, y.id));
        for (const r of sorted) {
          const isG = isGroup(store, r.target);
          let line = `MATCH: rule_id=${r.id} effect=${r.effect} action=${r.action} resource=${r.resource} specificity=${segCount(r.resource)} target_type=${isG ? 'group' : 'principal'} target_id=${r.target}`;
          if (isG) line += ` membership_path=${membershipPath(store, r.target, args.principal)}`;
          out += line + '\n';
        }
      }
      return { out, mutated: false };
    }
    case 'move-resource': {
      requirePath(args.from, 'from');
      requirePath(args.to, 'to');
      if (args.from === args.to) throw new UsageError('--from and --to are identical');
      let changed = 0;
      for (const r of store.rules) {
        let rest = null;
        if (args.from === '/') {
          rest = r.resource === '/' ? '' : r.resource;
        } else if (r.resource === args.from) {
          rest = '';
        } else if (r.resource.startsWith(args.from + '/')) {
          rest = r.resource.slice(args.from.length);
        }
        if (rest === null) continue;
        let next;
        if (args.to === '/') next = rest === '' ? '/' : rest;
        else next = args.to + rest;
        if (next !== r.resource) {
          r.resource = next;
          changed++;
        }
      }
      if (changed === 0) throw new UsageError('no rules affected by move');
      return { out: '', mutated: true };
    }
    default:
      throw new UsageError(`unknown command: ${cmd}`);
  }
}

// ---------------------------------------------------------------- main

function main(argv) {
  let out = '';
  let err = '';
  let code = 0;
  try {
    const { cmd, args } = parseArgs(argv);
    const file = args.store;
    if (file === '') throw new UsageError('--store must not be empty');
    if (cmd === 'init') {
      if (fs.existsSync(file)) throw new UsageError(`store already exists: ${file}`);
      const dir = path.dirname(path.resolve(file));
      if (!fs.existsSync(dir)) throw new UsageError(`directory does not exist: ${dir}`);
      saveStore(file, emptyStore());
    } else {
      const store = loadStore(file);
      const res = run(cmd, args, store);
      if (res.mutated) saveStore(file, store);
      out = res.out;
    }
  } catch (e) {
    out = '';
    if (e instanceof CorruptError) {
      code = 3;
      err = `grantline: store corruption detected: ${e.message}\n`;
    } else if (e instanceof UsageError) {
      code = 1;
      err = `grantline: ${e.message}\n`;
    } else {
      code = 1;
      err = `grantline: ${e && e.message ? e.message : String(e)}\n`;
    }
  }
  if (out) process.stdout.write(out);
  if (err) process.stderr.write(err);
  process.exitCode = code;
}

module.exports = { main, parseTimestamp, isValidPath, evaluate };
