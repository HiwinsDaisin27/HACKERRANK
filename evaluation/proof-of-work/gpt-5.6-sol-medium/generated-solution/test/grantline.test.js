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
