#!/usr/bin/env node
/**
 * Second calibration stub: implements groups/grants but wrong precedence (last matching rule wins).
 * Simulates a common single-pass model failure mode.
 */
import fs from 'fs';
import path from 'path';

const args = process.argv.slice(2);
const cmd = args[0];

function flag(name) {
  const i = args.indexOf('--' + name);
  return i >= 0 ? args[i + 1] : undefined;
}

function load(store) {
  return JSON.parse(fs.readFileSync(store, 'utf8'));
}
function save(store, data) {
  const dir = path.dirname(store);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(store, JSON.stringify(data, null, 2) + '\n');
}

function groupsOf(data, principal) {
  const out = new Set();
  const q = [];
  for (const [g, v] of Object.entries(data.groups || {})) {
    if (v.members.includes(principal)) q.push(g);
  }
  while (q.length) {
    const g = q.shift();
    if (out.has(g)) continue;
    out.add(g);
    for (const [p, v] of Object.entries(data.groups || {})) {
      if (v.members.includes(g)) q.push(p);
    }
  }
  return out;
}

function decide(data, principal, resource, action) {
  const rules = (data.rules || []).filter((r) => r.action === action);
  let last = null;
  for (const r of rules) {
    const targets =
      r.target_type === 'principal'
        ? r.target_id === principal
        : groupsOf(data, principal).has(r.target_id);
    if (!targets) continue;
    if (resource === r.resource || resource.startsWith(r.resource + '/')) {
      last = r;
    }
  }
  return last?.effect === 'allow' ? 'ALLOW' : 'DENY';
}

try {
  const store = flag('store');
  if (cmd === 'init') {
    save(store, { version: 1, principals: [], groups: {}, rules: [], next_rule_seq: 1 });
  } else if (cmd === 'add-principal') {
    const d = load(store);
    d.principals.push(flag('id'));
    save(store, d);
  } else if (cmd === 'add-group') {
    const d = load(store);
    d.groups[flag('id')] = { members: [] };
    save(store, d);
  } else if (cmd === 'add-group-member') {
    const d = load(store);
    d.groups[flag('group')].members.push(flag('member'));
    save(store, d);
  } else if (cmd === 'grant' || cmd === 'deny') {
    const d = load(store);
    const id = `rule-${d.next_rule_seq++}`;
    const target = flag('principal-or-group');
    d.rules.push({
      id,
      target_type: d.principals.includes(target) ? 'principal' : 'group',
      target_id: target,
      resource: flag('resource'),
      action: flag('action'),
      effect: cmd === 'grant' ? 'allow' : 'deny',
      valid_from: null,
      valid_until: null,
    });
    save(store, d);
  } else if (cmd === 'revoke') {
    const d = load(store);
    d.rules = d.rules.filter((r) => r.id !== flag('rule-id'));
    save(store, d);
  } else if (cmd === 'query') {
    console.log(decide(load(store), flag('principal'), flag('resource'), flag('action')));
  } else if (cmd === 'explain') {
    const d = load(store);
    const decision = decide(d, flag('principal'), flag('resource'), flag('action'));
    console.log(`DECISION: ${decision}\nMATCH: none\n`);
  } else {
    throw new Error('unsupported');
  }
} catch (e) {
  process.stderr.write(`grantline: ${e.message}\n`);
  process.exit(1);
}
