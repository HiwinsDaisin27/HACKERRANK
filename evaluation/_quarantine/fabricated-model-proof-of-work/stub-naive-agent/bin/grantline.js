#!/usr/bin/env node
/** Deliberately incomplete agent-style stub for scoring calibration (<30%). */
import fs from 'fs';

const args = process.argv.slice(2);
const cmd = args[0];
const storeIdx = args.indexOf('--store');
const store = storeIdx >= 0 ? args[storeIdx + 1] : null;

function load() {
  return JSON.parse(fs.readFileSync(store, 'utf8'));
}
function save(data) {
  fs.writeFileSync(store, JSON.stringify(data));
}

try {
  if (cmd === 'init') {
    save({ principals: [], groups: {}, rules: [] });
  } else if (cmd === 'add-principal') {
    const id = args[args.indexOf('--id') + 1];
    const s = load();
    s.principals.push(id);
    save(s);
  } else if (cmd === 'grant') {
    const s = load();
    s.rules = s.rules || [];
    s.rules.push({ effect: 'allow', action: args[args.indexOf('--action') + 1], resource: args[args.indexOf('--resource') + 1], target: args[args.indexOf('--principal-or-group') + 1] });
    save(s);
  } else if (cmd === 'query') {
    const s = load();
    const p = args[args.indexOf('--principal') + 1];
    const r = s.rules?.find((x) => x.target === p && x.effect === 'allow');
    console.log(r ? 'ALLOW' : 'DENY');
  } else if (cmd === 'explain') {
    console.log('DECISION: DENY\nMATCH: none\n');
  } else {
    process.stderr.write('grantline: not implemented\n');
    process.exit(1);
  }
} catch (e) {
  process.stderr.write(`grantline: ${e.message}\n`);
  process.exit(1);
}
