# Raw Model Response

```
===FILE: package.json===
{
  "name": "grantline",
  "version": "1.0.0",
  "description": "Persistent headless authorization CLI",
  "license": "MIT",
  "type": "commonjs",
  "main": "src/grantline.js",
  "bin": {
    "grantline": "bin/grantline.js"
  },
  "scripts": {
    "start": "node bin/grantline.js"
  },
  "engines": {
    "node": ">=18"
  }
}
===END FILE===
===FILE: bin/grantline.js===
#!/usr/bin/env node
'use strict';
const { run } = require('../src/grantline');
run(process.argv.slice(2));
===END FILE===
===FILE: src/grantline.js===
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ACTIONS = new Set(['read', 'write', 'admin']);
const EFFECTS = new Set(['allow', 'deny']);
const TARGETTYPES = new Set(['principal', 'group']);
const IDPATTERN = /^[A-Za-z0-9._-]+$/;
const RULEIDPATTERN = /^r([1-9][0-9]*)$/;
const TIMESTAMPPATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const COMMANDOPTIONS = {
  init: {
    required: ['store'],
    optional: []
  },
  'add-principal': {
    required: ['store', 'id'],
    optional: []
  },
  'add-group': {
    required: ['store', 'id'],
    optional: []
  },
  'add-group-member': {
    required: ['store', 'group', 'member'],
    optional: []
  },
  'remove-group-member': {
    required: ['store', 'group', 'member'],
    optional: []
  },
  grant: {
    required: ['store', 'principal-or-group', 'resource', 'action'],
    optional: ['valid-from', 'valid-until']
  },
  deny: {
    required: ['store', 'principal-or-group', 'resource', 'action'],
    optional: ['valid-from', 'valid-until']
  },
  revoke: {
    required: ['store', 'rule-id'],
    optional: []
  },
  query: {
    required: ['store', 'principal', 'resource', 'action'],
    optional: ['at']
  },
  explain: {
    required: ['store', 'principal', 'resource', 'action'],
    optional: ['at']
  },
  'move-resource': {
    required: ['store', 'from', 'to'],
    optional: []
  }
};
class GrantlineError extends Error {
  constructor(message, exitCode = 1) {
    super(message);
    this.name = 'GrantlineError';
    this.exitCode = exitCode;
  }
}
class StoreCorruptionError extends GrantlineError {
  constructor(reason) {
    super(`store corruption detected: ${sanitizeReason(reason)}`, 3);
    this.name = 'StoreCorruptionError';
  }
}
function sanitizeReason(reason) {
  return String(reason).replace(/[\r\n]+/g, ' ').trim() || 'invalid store';
}
function fail(message) {
  throw new GrantlineError(message, 1);
}
function corruption(reason) {
  throw new StoreCorruptionError(reason);
}
function own(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}
function exactKeys(object, expectedKeys) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) {
    return false;
  }
  const actual = Object.keys(object).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length) {
    return false;
  }
  return actual.every((key, index) => key === expected[index]);
}
function isValidId(value) {
  return typeof value === 'string' && IDPATTERN.test(value);
}
function isValidResource(resource) {
  if (typeof resource !== 'string' || !resource.startsWith('/')) {
    return false;
  }
  if (resource === '/') {
    return true;
  }
  if (resource.endsWith('/') || resource.includes('//')) {
    return false;
  }
  return resource
    .slice(1)
    .split('/')
    .every(segment => segment.length > 0);
}
function parseTimestamp(value, label) {
  if (typeof value !== 'string') {
    fail(`${label} must be an ISO 8601 timestamp`);
  }
  const match = TIMESTAMPPATTERN.exec(value);
  if (!match) {
    fail(`${label} must be an ISO 8601 timestamp`);
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const zone = match[8];
  if (month < 1 || month > 12) {
    fail(`${label} must be an ISO 8601 timestamp`);
  }
  const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (day < 1 || day > daysInMonth) {
    fail(`${label} must be an ISO 8601 timestamp`);
  }
  if (hour > 23 || minute > 59 || second > 59) {
    fail(`${label} must be an ISO 8601 timestamp`);
  }
  if (zone !== 'Z' && zone) {
    const offsetHour = Number(zone.slice(1, 3));
    const offsetMinute = Number(zone.slice(4, 6));
    if (offsetHour > 23 || offsetMinute > 59) {
      fail(`${label} must be an ISO 8601 timestamp`);
    }
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    fail(`${label} must be an ISO 8601 timestamp`);
  }
  return milliseconds;
}
function parseStoredTimestamp(value, label) {
  try {
    return parseTimestamp(value, label);
  } catch (error) {
    corruption(`${label} is invalid`);
  }
}
function validateTimeWindow(validFrom, validUntil, source = 'rule') {
  let fromMilliseconds = null;
  let untilMilliseconds = null;
  if (validFrom !== null && validFrom !== undefined) {
    fromMilliseconds =
      source === 'rule'
        ? parseStoredTimestamp(validFrom, 'rule valid_from')
        : parseTimestamp(validFrom, '--valid-from');
  }
  if (validUntil !== null && validUntil !== undefined) {
    untilMilliseconds =
      source === 'rule'
        ? parseStoredTimestamp(validUntil, 'rule valid_until')
        : parseTimestamp(validUntil, '--valid-until');
  }
  if (
    fromMilliseconds !== null &&
    untilMilliseconds !== null &&
    fromMilliseconds >= untilMilliseconds
  ) {
    if (source === 'rule') {
      corruption('rule valid_from must be earlier than valid_until');
    }
    fail('--valid-from must be earlier than --valid-until');
  }
  return {
    fromMilliseconds,
    untilMilliseconds
  };
}
function createEmptyStore() {
  return {
    version: 1,
    next_rule_id: 1,
    principals: [],
    groups: [],
    rules: []
  };
}
function validateStore(store) {
  if (
    !exactKeys(store, [
      'version',
      'next_rule_id',
      'principals',
      'groups',
      'rules'
    ])
  ) {
    corruption('invalid root structure');
  }
  if (store.version !== 1) {
    corruption('unsupported store version');
  }
  if (
    !Number.isSafeInteger(store.next_rule_id) ||
    store.next_rule_id < 1
  ) {
    corruption('invalid next_rule_id');
  }
  if (!Array.isArray(store.principals)) {
    corruption('principals must be an array');
  }
  if (!Array.isArray(store.groups)) {
    corruption('groups must be an array');
  }
  if (!Array.isArray(store.rules)) {
    corruption('rules must be an array');
  }
  const principalIds = new Set();
  for (const principalId of store.principals) {
    if (!isValidId(principalId)) {
      corruption('invalid principal id');
    }
    if (principalIds.has(principalId)) {
      corruption(`duplicate principal id ${principalId}`);
    }
    principalIds.add(principalId);
  }
  const groupIds = new Set();
  const groupMap = new Map();
  for (const group of store.groups) {
    if (!exactKeys(group, ['id', 'members'])) {
      corruption('invalid group structure');
    }
    if (!isValidId(group.id)) {
      corruption('invalid group id');
    }
    if (principalIds.has(group.id)) {
      corruption(`id collision for ${group.id}`);
    }
    if (groupIds.has(group.id)) {
      corruption(`duplicate group id ${group.id}`);
    }
    if (!Array.isArray(group.members)) {
      corruption(`members for group ${group.id} must be an array`);
    }
    groupIds.add(group.id);
    groupMap.set(group.id, group);
  }
  for (const group of store.groups) {
    const members = new Set();
    for (const memberId of group.members) {
      if (!isValidId(memberId)) {
        corruption(`invalid member id in group ${group.id}`);
      }
      if (members.has(memberId)) {
        corruption(`duplicate member ${memberId} in group ${group.id}`);
      }
      if (!principalIds.has(memberId) && !groupIds.has(memberId)) {
        corruption(`dangling member ${memberId} in group ${group.id}`);
      }
      members.add(memberId);
    }
  }
  validateAcyclicGroups(groupMap, groupIds);
  const ruleIds = new Set();
  let largestRuleNumber = 0;
  for (const rule of store.rules) {
    if (
      !exactKeys(rule, [
        'id',
        'effect',
        'target_type',
        'target_id',
        'resource',
        'action',
        'valid_from',
        'valid_until'
      ])
    ) {
      corruption('invalid rule structure');
    }
    if (typeof rule.id !== 'string') {
      corruption('invalid rule id');
    }
    const ruleIdMatch = RULEIDPATTERN.exec(rule.id);
    if (!ruleIdMatch) {
      corruption(`invalid rule id ${rule.id}`);
    }
    if (ruleIds.has(rule.id)) {
      corruption(`duplicate rule id ${rule.id}`);
    }
    const ruleNumber = Number(ruleIdMatch[1]);
    if (!Number.isSafeInteger(ruleNumber)) {
      corruption(`invalid rule id ${rule.id}`);
    }
    largestRuleNumber = Math.max(largestRuleNumber, ruleNumber);
    ruleIds.add(rule.id);
    if (!EFFECTS.has(rule.effect)) {
      corruption(`invalid effect for rule ${rule.id}`);
    }
    if (!TARGETTYPES.has(rule.target_type)) {
      corruption(`invalid target type for rule ${rule.id}`);
    }
    if (!isValidId(rule.target_id)) {
      corruption(`invalid target id for rule ${rule.id}`);
    }
    if (
      rule.target_type === 'principal' &&
      !principalIds.has(rule.target_id)
    ) {
      corruption(`dangling target for rule ${rule.id}`);
    }
    if (rule.target_type === 'group' && !groupIds.has(rule.target_id)) {
      corruption(`dangling target for rule ${rule.id}`);
    }
    if (!isValidResource(rule.resource)) {
      corruption(`invalid resource for rule ${rule.id}`);
    }
    if (!ACTIONS.has(rule.action)) {
      corruption(`invalid action for rule ${rule.id}`);
    }
    if (
      rule.valid_from !== null &&
      typeof rule.valid_from !== 'string'
    ) {
      corruption(`invalid valid_from for rule ${rule.id}`);
    }
    if (
      rule.valid_until !== null &&
      typeof rule.valid_until !== 'string'
    ) {
      corruption(`invalid valid_until for rule ${rule.id}`);
    }
    validateTimeWindow(rule.valid_from, rule.valid_until, 'rule');
  }
  if (store.next_rule_id <= largestRuleNumber) {
    corruption('next_rule_id does not follow existing rule ids');
  }
  return {
    principalIds,
    groupIds,
    groupMap
  };
}
function validateAcyclicGroups(groupMap, groupIds) {
  const state = new Map();
  function visit(groupId) {
    const currentState = state.get(groupId) || 0;
    if (currentState === 1) {
      corruption('group nesting cycle detected');
    }
    if (currentState === 2) {
      return;
    }
    state.set(groupId, 1);
    const group = groupMap.get(groupId);
    for (const memberId of group.members) {
      if (groupIds.has(memberId)) {
        visit(memberId);
      }
    }
    state.set(groupId, 2);
  }
  for (const groupId of groupIds) {
    visit(groupId);
  }
}
function readStore(storePath) {
  let bytes;
  try {
    bytes = fs.readFileSync(storePath);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      fail('store does not exist');
    }
    fail(`cannot read store: ${error.message}`);
  }
  let store;
  try {
    store = JSON.parse(bytes.toString('utf8'));
  } catch {
    corruption('invalid JSON');
  }
  const indexes = validateStore(store);
  return { store, indexes };
}
function serializeStore(store) {
  return `${JSON.stringify(store, null, 2)}\n`;
}
function initializeStore(storePath) {
  if (fs.existsSync(storePath)) {
    readStore(storePath);
    fail('store already exists');
  }
  const directory = path.dirname(path.resolve(storePath));
  const basename = path.basename(storePath);
  const temporaryPath = path.join(
    directory,
    `.${basename}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`
  );
  try {
    fs.writeFileSync(temporaryPath, serializeStore(createEmptyStore()), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600
    });
    try {
      fs.linkSync(temporaryPath, storePath);
    } catch (error) {
      if (error && error.code === 'EEXIST') {
        fail('store already exists');
      }
      throw error;
    }
  } catch (error) {
    if (error instanceof GrantlineError) {
      throw error;
    }
    fail(`cannot initialize store: ${error.message}`);
  } finally {
    try {
      fs.unlinkSync(temporaryPath);
    } catch (error) {
      if (!error || error.code !== 'ENOENT') {
        // Cleanup failure does not invalidate a successfully created store.
      }
    }
  }
}
function writeStoreAtomically(storePath, store) {
  const directory = path.dirname(path.resolve(storePath));
  const basename = path.basename(storePath);
  const temporaryPath = path.join(
    directory,
    `.${basename}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`
  );
  let mode = 0o600;
  try {
    mode = fs.statSync(storePath).mode & 0o777;
  } catch (error) {
    fail(`cannot inspect store: ${error.message}`);
  }
  try {
    fs.writeFileSync(temporaryPath, serializeStore(store), {
      encoding: 'utf8',
      flag: 'wx',
      mode
    });
    const descriptor = fs.openSync(temporaryPath, 'r');
    try {
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
    fs.renameSync(temporaryPath, storePath);
  } catch (error) {
    try {
      fs.unlinkSync(temporaryPath);
    } catch (cleanupError) {
      if (!cleanupError || cleanupError.code !== 'ENOENT') {
        // Preserve the original write error.
      }
    }
    fail(`cannot update store: ${error.message}`);
  }
}
function parseArguments(argv) {
  if (argv.length === 0) {
    fail('missing command');
  }
  const command = argv[0];
  if (!own(COMMANDOPTIONS, command)) {
    fail(`unknown command: ${command}`);
  }
  const options = {};
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--') || token.length === 2) {
      fail(`unexpected argument: ${token}`);
    }
    const name = token.slice(2);
    if (own(options, name)) {
      fail(`duplicate option: --${name}`);
    }
    if (index + 1 >= argv.length || argv[index + 1].startsWith('--')) {
      fail(`missing value for --${name}`);
    }
    options[name] = argv[index + 1];
    index += 1;
  }
  if (!own(options, 'store') || options.store.length === 0) {
    fail('missing required option: --store');
  }
  return { command, options };
}
function validateCommandOptions(command, options) {
  const specification = COMMANDOPTIONS[command];
  const allowed = new Set([
    ...specification.required,
    ...specification.optional
  ]);
  for (const optionName of Object.keys(options)) {
    if (!allowed.has(optionName)) {
      fail(`unknown option for ${command}: --${optionName}`);
    }
    if (options[optionName].length === 0) {
      fail(`empty value for --${optionName}`);
    }
  }
  for (const optionName of specification.required) {
    if (!own(options, optionName)) {
      fail(`missing required option: --${optionName}`);
    }
  }
}
function requireValidId(value, label) {
  if (!isValidId(value)) {
    fail(`${label} is invalid`);
  }
}
function requireValidResource(value, label) {
  if (!isValidResource(value)) {
    fail(`${label} is invalid`);
  }
}
function requireValidAction(value) {
  if (!ACTIONS.has(value)) {
    fail('--action must be read, write, or admin');
  }
}
function cloneStore(store) {
  return JSON.parse(JSON.stringify(store));
}
function findGroup(store, groupId) {
  return store.groups.find(group => group.id === groupId);
}
function addPrincipal(store, options) {
  requireValidId(options.id, '--id');
  if (
    store.principals.includes(options.id) ||
    store.groups.some(group => group.id === options.id)
  ) {
    fail(`id already exists: ${options.id}`);
  }
  const nextStore = cloneStore(store);
  nextStore.principals.push(options.id);
  return nextStore;
}
function addGroup(store, options) {
  requireValidId(options.id, '--id');
  if (
    store.principals.includes(options.id) ||
    store.groups.some(group => group.id === options.id)
  ) {
    fail(`id already exists: ${options.id}`);
  }
  const nextStore = cloneStore(store);
  nextStore.groups.push({
    id: options.id,
    members: []
  });
  return nextStore;
}
function addGroupMember(store, options) {
  requireValidId(options.group, '--group');
  requireValidId(options.member, '--member');
  const group = findGroup(store, options.group);
  if (!group) {
    fail(`group does not exist: ${options.group}`);
  }
  const memberExists =
    store.principals.includes(options.member) ||
    store.groups.some(candidate => candidate.id === options.member);
  if (!memberExists) {
    fail(`member does not exist: ${options.member}`);
  }
  if (group.members.includes(options.member)) {
    fail(`membership already exists: ${options.group} -> ${options.member}`);
  }
  const nextStore = cloneStore(store);
  findGroup(nextStore, options.group).members.push(options.member);
  try {
    validateStore(nextStore);
  } catch (error) {
    if (
      error instanceof StoreCorruptionError &&
      error.message.includes('group nesting cycle detected')
    ) {
      fail('group membership would create a cycle');
    }
    throw error;
  }
  return nextStore;
}
function removeGroupMember(store, options) {
  requireValidId(options.group, '--group');
  requireValidId(options.member, '--member');
  const group = findGroup(store, options.group);
  if (!group) {
    fail(`group does not exist: ${options.group}`);
  }
  if (!group.members.includes(options.member)) {
    fail(`direct membership does not exist: ${options.group} -> ${options.member}`);
  }
  const nextStore = cloneStore(store);
  const nextGroup = findGroup(nextStore, options.group);
  nextGroup.members = nextGroup.members.filter(
    memberId => memberId !== options.member
  );
  return nextStore;
}
function addRule(store, options, effect) {
  requireValidId(options['principal-or-group'], '--principal-or-group');
  requireValidResource(options.resource, '--resource');
  requireValidAction(options.action);
  const targetId = options['principal-or-group'];
  let targetType;
  if (store.principals.includes(targetId)) {
    targetType = 'principal';
  } else if (store.groups.some(group => group.id === targetId)) {
    targetType = 'group';
  } else {
    fail(`target does not exist: ${targetId}`);
  }
  const validFrom = own(options, 'valid-from')
    ? options['valid-from']
    : null;
  const validUntil = own(options, 'valid-until')
    ? options['valid-until']
    : null;
  validateTimeWindow(validFrom, validUntil, 'input');
  const nextStore = cloneStore(store);
  const ruleId = `r${nextStore.next_rule_id}`;
  nextStore.rules.push({
    id: ruleId,
    effect,
    target_type: targetType,
    target_id: targetId,
    resource: options.resource,
    action: options.action,
    valid_from: validFrom,
    valid_until: validUntil
  });
  nextStore.next_rule_id += 1;
  return nextStore;
}
function revokeRule(store, options) {
  const ruleIndex = store.rules.findIndex(
    rule => rule.id === options['rule-id']
  );
  if (ruleIndex === -1) {
    fail(`rule does not exist: ${options['rule-id']}`);
  }
  const nextStore = cloneStore(store);
  nextStore.rules.splice(ruleIndex, 1);
  return nextStore;
}
function resourceIsAtOrBelow(resource, ancestor) {
  if (ancestor === '/') {
    return resource.startsWith('/');
  }
  return resource === ancestor || resource.startsWith(`${ancestor}/`);
}
function replaceResourcePrefix(resource, from, to) {
  const suffix = from === '/' ? resource.slice(1) : resource.slice(from.length);
  if (to === '/') {
    if (suffix.length === 0) {
      return '/';
    }
    return suffix.startsWith('/') ? suffix : `/${suffix}`;
  }
  if (suffix.length === 0) {
    return to;
  }
  return suffix.startsWith('/') ? `${to}${suffix}` : `${to}/${suffix}`;
}
function moveResource(store, options) {
  requireValidResource(options.from, '--from');
  requireValidResource(options.to, '--to');
  if (options.from === options.to) {
    fail('--from and --to must differ');
  }
  const matchingRules = store.rules.filter(rule =>
    resourceIsAtOrBelow(rule.resource, options.from)
  );
  if (matchingRules.length === 0) {
    fail('no rules would change');
  }
  const nextStore = cloneStore(store);
  for (const rule of nextStore.rules) {
    if (resourceIsAtOrBelow(rule.resource, options.from)) {
      rule.resource = replaceResourcePrefix(
        rule.resource,
        options.from,
        options.to
      );
    }
  }
  return nextStore;
}
function resourceSpecificity(resource) {
  if (resource === '/') {
    return 1;
  }
  return resource.slice(1).split('/').length;
}
function isRuleInEffect(rule, atMilliseconds) {
  if (
    rule.valid_from !== null &&
    atMilliseconds < Date.parse(rule.valid_from)
  ) {
    return false;
  }
  if (
    rule.valid_until !== null &&
    atMilliseconds >= Date.parse(rule.valid_until)
  ) {
    return false;
  }
  return true;
}
function compareChains(left, right) {
  return left.join('>').localeCompare(right.join('>'));
}
function createMembershipPathFinder(store, principalId) {
  const principalIds = new Set(store.principals);
  const groupIds = new Set(store.groups.map(group => group.id));
  const groupMap = new Map(
    store.groups.map(group => [group.id, group])
  );
  const memo = new Map();
  function find(groupId) {
    if (memo.has(groupId)) {
      return memo.get(groupId);
    }
    const group = groupMap.get(groupId);
    const candidates = [];
    if (group.members.includes(principalId) && principalIds.has(principalId)) {
      candidates.push([groupId]);
    }
    for (const memberId of group.members) {
      if (!groupIds.has(memberId)) {
        continue;
      }
      const childPath = find(memberId);
      if (childPath !== null) {
        candidates.push([groupId, ...childPath]);
      }
    }
    candidates.sort(compareChains);
    const best = candidates.length > 0 ? candidates[0] : null;
    memo.set(groupId, best);
    return best;
  }
  return find;
}
function evaluate(store, options) {
  requireValidId(options.principal, '--principal');
  requireValidResource(options.resource, '--resource');
  requireValidAction(options.action);
  if (!store.principals.includes(options.principal)) {
    fail(`principal does not exist: ${options.principal}`);
  }
  const atMilliseconds = own(options, 'at')
    ? parseTimestamp(options.at, '--at')
    : Date.now();
  const findMembershipPath = createMembershipPathFinder(
    store,
    options.principal
  );
  const applicable = [];
  for (const rule of store.rules) {
    if (rule.action !== options.action) {
      continue;
    }
    if (!resourceIsAtOrBelow(options.resource, rule.resource)) {
      continue;
    }
    if (!isRuleInEffect(rule, atMilliseconds)) {
      continue;
    }
    let membershipPath = null;
    if (rule.target_type === 'principal') {
      if (rule.target_id !== options.principal) {
        continue;
      }
    } else {
      membershipPath = findMembershipPath(rule.target_id);
      if (membershipPath === null) {
        continue;
      }
    }
    applicable.push({
      rule,
      specificity: resourceSpecificity(rule.resource),
      membershipPath
    });
  }
  if (applicable.length === 0) {
    return {
      decision: 'DENY',
      matches: []
    };
  }
  const winningSpecificity = Math.max(
    ...applicable.map(entry => entry.specificity)
  );
  const atWinningSpecificity = applicable.filter(
    entry => entry.specificity === winningSpecificity
  );
  const denies = atWinningSpecificity.filter(
    entry => entry.rule.effect === 'deny'
  );
  const decision = denies.length > 0 ? 'DENY' : 'ALLOW';
  const matches =
    decision === 'DENY'
      ? denies
      : atWinningSpecificity.filter(
          entry => entry.rule.effect === 'allow'
        );
  matches.sort((left, right) =>
    left.rule.id.localeCompare(right.rule.id)
  );
  return {
    decision,
    matches
  };
}
function formatExplanation(result) {
  const lines = [`DECISION: ${result.decision}`];
  if (result.matches.length === 0) {
    lines.push('MATCH: none');
    return `${lines.join('\n')}\n`;
  }
  for (const match of result.matches) {
    const rule = match.rule;
    let line =
      `MATCH: rule_id=${rule.id}` +
      ` effect=${rule.effect}` +
      ` action=${rule.action}` +
      ` resource=${rule.resource}` +
      ` specificity=${match.specificity}` +
      ` target_type=${rule.target_type}` +
      ` target_id=${rule.target_id}`;
    if (rule.target_type === 'group') {
      line += ` membership_path=${match.membershipPath.join('>')}`;
    }
    lines.push(line);
  }
  return `${lines.join('\n')}\n`;
}
function execute(command, options) {
  if (command === 'init') {
    validateCommandOptions(command, options);
    initializeStore(options.store);
    return;
  }
  const { store } = readStore(options.store);
  validateCommandOptions(command, options);
  let nextStore = null;
  switch (command) {
    case 'add-principal':
      nextStore = addPrincipal(store, options);
      break;
    case 'add-group':
      nextStore = addGroup(store, options);
      break;
    case 'add-group-member':
      nextStore = addGroupMember(store, options);
      break;
    case 'remove-group-member':
      nextStore = removeGroupMember(store, options);
      break;
    case 'grant':
      nextStore = addRule(store, options, 'allow');
      break;
    case 'deny':
      nextStore = addRule(store, options, 'deny');
      break;
    case 'revoke':
      nextStore = revokeRule(store, options);
      break;
    case 'move-resource':
      nextStore = moveResource(store, options);
      break;
    case 'query': {
      const result = evaluate(store, options);
      process.stdout.write(`${result.decision}\n`);
      return;
    }
    case 'explain': {
      const result = evaluate(store, options);
      process.stdout.write(formatExplanation(result));
      return;
    }
    default:
      fail(`unknown command: ${command}`);
  }
  validateStore(nextStore);
  writeStoreAtomically(options.store, nextStore);
}
function run(argv) {
  try {
    const { command, options } = parseArguments(argv);
    execute(command, options);
  } catch (error) {
    if (error instanceof GrantlineError) {
      process.stderr.write(`grantline: ${error.message}\n`);
      process.exitCode = error.exitCode;
      return;
    }
    const message =
      error && typeof error.message === 'string'
        ? error.message
        : 'unexpected failure';
    process.stderr.write(`grantline: ${sanitizeReason(message)}\n`);
    process.exitCode = 1;
  }
}
module.exports = {
  run
};
===END FILE===
```
