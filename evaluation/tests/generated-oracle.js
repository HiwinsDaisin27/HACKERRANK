import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { runGrantline, sha256File } from '../lib/harness.js';

const ACTIONS = ['read', 'write', 'admin'];
const TS = [
  '2024-01-01T00:00:00Z',
  '2025-01-01T00:00:00Z',
  '2025-06-01T00:00:00Z',
  '2025-06-01T00:00:00.000Z',
  '2025-12-31T23:59:59Z',
  '2026-01-01T00:00:00Z',
];

function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function seedFromString(s) {
  const h = crypto.createHash('sha256').update(s).digest();
  return h.readUInt32LE(0);
}

function pick(rng, arr) {
  return arr[Math.floor(rng() * arr.length)];
}

function oracleBin() {
  return process.env.GRANTLINE_ORACLE_BIN || 'node reference/bin/grantline.js';
}

function candidateBin() {
  return process.env.GRANTLINE_BIN || oracleBin();
}

function withStore(args, store) {
  return [args[0], '--store', store, ...args.slice(1)];
}

function runBin(binSpec, args) {
  const prev = process.env.GRANTLINE_BIN;
  process.env.GRANTLINE_BIN = binSpec;
  const res = runGrantline(args);
  process.env.GRANTLINE_BIN = prev;
  return res;
}

// ---------------------------------------------------------------------------
// Format-agnostic store helpers
// ---------------------------------------------------------------------------

/**
 * Inject a member into a group, handling two common JSON layouts:
 *   - Object layout:  groups[id] = { members: [...] }
 *   - Array layout:   groups[id] = [...]
 * Returns true if the injection succeeded, false if the layout is unknown.
 */
function injectMember(data, groupId, memberId) {
  const groups = data.groups || {};
  if (!groups[groupId]) return false;
  const g = groups[groupId];
  if (Array.isArray(g)) {
    if (!g.includes(memberId)) g.push(memberId);
    return true;
  }
  if (g && Array.isArray(g.members)) {
    if (!g.members.includes(memberId)) g.members.push(memberId);
    return true;
  }
  return false; // Unknown layout — do not crash.
}

/**
 * Format-agnostic tamper: introduce a two-node cycle between the first two
 * groups in the store. Skips silently if the store has fewer than two groups
 * or uses an unrecognised format, so the test session never crashes.
 */
function tamperTwoNodeCycle(storePath) {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  } catch {
    return; // Unreadable / non-JSON store – skip.
  }
  const ids = Object.keys(data.groups || {});
  if (ids.length < 2) return;
  const g1 = ids[0];
  const g2 = ids[1];
  if (!injectMember(data, g2, g1)) return; // Unknown layout – skip.
  try {
    fs.writeFileSync(storePath, JSON.stringify(data, null, 2) + '\n');
  } catch {
    // Write failure – skip silently.
  }
}

/**
 * Format-agnostic rule list extraction.
 * Tries common top-level key names used by different implementations.
 */
function readRules(storePath) {
  try {
    const data = JSON.parse(fs.readFileSync(storePath, 'utf8'));
    if (Array.isArray(data.rules)) return data.rules;
    for (const key of ['policies', 'grants', 'entries', 'acl']) {
      if (Array.isArray(data[key])) return data[key];
    }
  } catch {
    // ignore
  }
  return [];
}

function buildOp(rng, ctx) {
  const kind = pick(rng, ctx.opKinds);
  switch (kind) {
    case 'add-principal': {
      const id = `p${ctx.nextP++}`;
      ctx.knownPrincipals.add(id);
      return { cmd: ['add-principal', '--id', id], type: 'mut' };
    }
    case 'add-group': {
      const id = `g${ctx.nextG++}`;
      ctx.knownGroups.add(id);
      return { cmd: ['add-group', '--id', id], type: 'mut' };
    }
    case 'add-member': {
      if (ctx.knownGroups.size === 0 || ctx.knownPrincipals.size + ctx.knownGroups.size < 2) {
        return buildOp(rng, ctx);
      }
      const group = pick(rng, [...ctx.knownGroups]);
      const candidates = [...ctx.knownPrincipals, ...ctx.knownGroups].filter((x) => x !== group);
      if (!candidates.length) return buildOp(rng, ctx);
      const member = pick(rng, candidates);
      if (rng() < 0.08) {
        return { cmd: ['add-group-member', '--group', group, '--member', group], type: 'bad', expectFail: true };
      }
      return { cmd: ['add-group-member', '--group', group, '--member', member], type: 'mut' };
    }
    case 'grant':
    case 'deny': {
      const targets = [...ctx.knownPrincipals, ...ctx.knownGroups];
      if (!targets.length) return buildOp(rng, ctx);
      const target = pick(rng, targets);
      const resource = pick(rng, ctx.resources);
      const action = pick(rng, ACTIONS);
      const cmd = [kind, '--principal-or-group', target, '--resource', resource, '--action', action];
      if (rng() < 0.35) {
        cmd.push('--valid-from', TS[0]);
        cmd.push('--valid-until', TS[4]);
      } else if (rng() < 0.5) {
        cmd.push('--valid-until', pick(rng, TS));
      }
      return { cmd, type: 'mut' };
    }
    case 'revoke': {
      if (!ctx.ruleIds.length) return buildOp(rng, ctx);
      const id = pick(rng, ctx.ruleIds);
      ctx.ruleIds = ctx.ruleIds.filter((r) => r !== id);
      return { cmd: ['revoke', '--rule-id', id], type: 'mut' };
    }
    case 'move': {
      if (ctx.resources.length < 2) return buildOp(rng, ctx);
      const from = pick(rng, ctx.resources.slice(0, 3));
      const to = pick(rng, [`/moved${ctx.nextM++}`, `/alt${ctx.nextM}`, `/z${ctx.nextM}`]);
      ctx.resources.push(to);
      return { cmd: ['move-resource', '--from', from, '--to', to], type: 'mut' };
    }
    case 'cycle-attempt': {
      return { cmd: ['add-group-member', '--group', 'g2', '--member', 'g0'], type: 'cycle', expectFail: true };
    }
    case 'tamper-query': {
      if (!ctx.knownPrincipals.size) return buildOp(rng, ctx);
      return { cmd: ['__tamper_cycle__'], type: 'tamper' };
    }
    case 'query':
    case 'explain': {
      if (!ctx.knownPrincipals.size) return buildOp(rng, ctx);
      const principal = pick(rng, [...ctx.knownPrincipals]);
      const resource = pick(rng, ctx.resources);
      const action = pick(rng, ACTIONS);
      const cmd = [kind, '--principal', principal, '--resource', resource, '--action', action];
      if (rng() < 0.7) cmd.push('--at', pick(rng, TS));
      return { cmd, type: 'read' };
    }
    default:
      return buildOp(rng, ctx);
  }
}

function syncRuleIds(ctx, storePath) {
  ctx.ruleIds = readRules(storePath).map((r) => r.id);
}

function runSession(sessionIndex, rng, stepCount) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grantline-gen-'));
  const storeO = path.join(dir, 'oracle.json');
  const storeC = path.join(dir, 'candidate.json');

  const ctx = {
    nextP: 0,
    nextG: 0,
    nextM: 0,
    knownPrincipals: new Set(),
    knownGroups: new Set(),
    resources: ['/a', '/a/b', '/a/b/c', '/x', '/x/y', '/app', '/app/v2', '/data', '/'],
    ruleIds: [],
    opKinds: [
      'add-principal',
      'add-group',
      'add-member',
      'grant',
      'deny',
      'grant',
      'query',
      'explain',
      'revoke',
      'move',
      'cycle-attempt',
      'tamper-query',
    ],
  };

  const ob = oracleBin();
  const cb = candidateBin();
  const selfCheck = ob === cb;

  let rO = runBin(ob, ['init', '--store', storeO]);
  let rC;
  if (selfCheck) {
    fs.copyFileSync(storeO, storeC);
    rC = rO;
  } else {
    rC = runBin(cb, ['init', '--store', storeC]);
  }
  if (rO.status !== 0 || rC.status !== 0) {
    return { ok: false, message: `init failed session ${sessionIndex}` };
  }

  const bootstrap = [
    ['add-principal', '--id', 'p0'],
    ['add-group', '--id', 'g0'],
    ['add-group', '--id', 'g1'],
    ['add-group', '--id', 'g2'],
    ['add-group-member', '--group', 'g0', '--member', 'g1'],
    ['add-group-member', '--group', 'g1', '--member', 'g2'],
    ['add-group-member', '--group', 'g2', '--member', 'p0'],
    ['deny', '--principal-or-group', 'g0', '--resource', '/a', '--action', 'read'],
    ['grant', '--principal-or-group', 'g2', '--resource', '/a/b', '--action', 'read'],
  ];
  for (const cmd of bootstrap) {
    rO = runBin(ob, withStore(cmd, storeO));
    if (selfCheck) {
      fs.copyFileSync(storeO, storeC);
      rC = rO;
    } else {
      rC = runBin(cb, withStore(cmd, storeC));
    }
    if (rO.status !== rC.status || rO.status !== 0) {
      return { ok: false, message: `bootstrap failed session ${sessionIndex}` };
    }
  }
  ctx.knownPrincipals.add('p0');
  ctx.knownGroups.add('g0');
  ctx.knownGroups.add('g1');
  ctx.knownGroups.add('g2');
  syncRuleIds(ctx, storeO);

  // Precedence probe: narrow allow at /a/b must beat broad deny at /a.
  // This directly detects a deny-first-across-all-matches bug (mutant-1).
  {
    const probeCmd = ['query', '--principal', 'p0', '--resource', '/a/b/probe', '--action', 'read'];
    const probeO = runBin(ob, withStore(probeCmd, storeO));
    const probeC = runBin(cb, withStore(probeCmd, storeC));
    if (probeO.status !== 0 || probeC.status !== 0) {
      return { ok: false, message: `session ${sessionIndex} precedence probe failed (status ${probeO.status}/${probeC.status})` };
    }
    if (probeO.stdout !== probeC.stdout) {
      return { ok: false, message: `session ${sessionIndex} precedence probe stdout mismatch: oracle=${probeO.stdout.trim()} candidate=${probeC.stdout.trim()}` };
    }
  }

  for (let step = 0; step < stepCount; step++) {
    const op = buildOp(rng, ctx);
    if (op.cmd[0] === '__tamper_cycle__') {
      const principal = pick(rng, [...ctx.knownPrincipals]);
      tamperTwoNodeCycle(storeO);
      tamperTwoNodeCycle(storeC);
      const q = ['query', '--principal', principal, '--resource', '/', '--action', 'read'];
      rO = runBin(ob, withStore(q, storeO));
      if (selfCheck) rC = rO;
      else rC = runBin(cb, withStore(q, storeC));
      if (rO.status !== rC.status) {
        return { ok: false, message: `session ${sessionIndex} tamper-query status ${rO.status} vs ${rC.status}` };
      }
      continue;
    }
    const argsO = withStore(op.cmd, storeO);
    const argsC = withStore(op.cmd, storeC);
    const hashBeforeO = sha256File(storeO);
    const hashBeforeC = sha256File(storeC);

    rO = runBin(ob, argsO);
    if (selfCheck) {
      if (rO.status === 0) fs.copyFileSync(storeO, storeC);
      rC = rO;
    } else {
      rC = runBin(cb, argsC);
    }

    if (rO.status !== rC.status) {
      return {
        ok: false,
        message: `session ${sessionIndex} step ${step} status ${rO.status} vs ${rC.status} cmd=${op.cmd.join(' ')}`,
      };
    }

    if (rO.status === 0 && (op.type === 'read' || op.cmd[0] === 'query' || op.cmd[0] === 'explain')) {
      if (rO.stdout !== rC.stdout) {
        return {
          ok: false,
          message: `session ${sessionIndex} step ${step} stdout mismatch ${op.cmd[0]}`,
        };
      }
    }

    if (rO.status !== 0) {
      const hashAfterO = sha256File(storeO);
      const hashAfterC = sha256File(storeC);
      // Each implementation must leave its own store unchanged on a failed op.
      // We do NOT cross-compare oracle vs candidate hashes — stores may use
      // different (but valid) persistence formats and will legitimately differ.
      if (hashAfterO !== hashBeforeO || hashAfterC !== hashBeforeC) {
        return { ok: false, message: `session ${sessionIndex} step ${step} store changed on failed op` };
      }
    } else {
      syncRuleIds(ctx, storeO);
    }
    if (selfCheck) fs.copyFileSync(storeO, storeC);
  }

  fs.rmSync(dir, { recursive: true, force: true });
  return { ok: true };
}

export function runGeneratedOracleSuite(options = {}) {
  const sessions = options.sessions ?? parseInt(process.env.GENERATED_SESSIONS || '400', 10);
  const baseSeed = process.env.GENERATED_SEED || 'grantline-generated-v1';
  let passed = 0;
  let firstFail = null;

  for (let i = 0; i < sessions; i++) {
    const rng = mulberry32(seedFromString(`${baseSeed}:${i}`));
    const steps = 10 + Math.floor(rng() * 15);
    const result = runSession(i, rng, steps);
    if (result.ok) passed++;
    else if (!firstFail) firstFail = result.message;
  }

  return {
    pass: passed === sessions,
    passed,
    total: sessions,
    message: firstFail || (passed === sessions ? undefined : `${passed}/${sessions}`),
  };
}
