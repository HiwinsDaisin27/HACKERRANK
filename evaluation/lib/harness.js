import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import crypto from 'crypto';

export function grantlineBin() {
  const fromEnv = process.env.GRANTLINE_BIN;
  if (fromEnv) return fromEnv;
  return 'grantline';
}

export function runGrantline(args, opts = {}) {
  const binSpec = grantlineBin();
  const parts = binSpec.split(/\s+/).filter(Boolean);
  const bin = parts[0];
  const prefixArgs = parts.slice(1);
  const res = spawnSync(bin, [...prefixArgs, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...opts.env },
    cwd: opts.cwd,
  });
  if (res.error) {
    const errorMsg = `[HARNESS SPAWN ERROR] ${res.error.message || res.error}`;
    console.error(errorMsg);
  }
  return {
    status: res.status ?? (res.error ? 127 : 0),
    stdout: res.stdout ?? '',
    stderr: res.stderr ?? '',
    error: res.error,
  };
}

export function tempStorePath(prefix = 'grantline') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix + '-'));
  return path.join(dir, 'store.json');
}

export function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function runScript(store, steps) {
  const outputs = [];
  for (const step of steps) {
    const args = step.args.map((a) =>
      typeof a === 'string' ? a.replace(/\{store\}/g, store) : a
    );
    const res = runGrantline(args);
    outputs.push({ step, res });
    if (step.expectStatus !== undefined && res.status !== step.expectStatus) {
      return {
        ok: false,
        outputs,
        message: `expected status ${step.expectStatus}, got ${res.status} stderr=${res.stderr}`,
      };
    }
    if (step.expectStdout !== undefined && res.stdout !== step.expectStdout) {
      return {
        ok: false,
        outputs,
        message: `stdout mismatch: expected ${JSON.stringify(step.expectStdout)} got ${JSON.stringify(res.stdout)}`,
      };
    }
    if (step.expectStdoutContains && !res.stdout.includes(step.expectStdoutContains)) {
      return {
        ok: false,
        outputs,
        message: `stdout missing ${step.expectStdoutContains}`,
      };
    }
    if (step.expectStderrContains && !res.stderr.includes(step.expectStderrContains)) {
      return {
        ok: false,
        outputs,
        message: `stderr missing ${step.expectStderrContains}`,
      };
    }
    if (step.expectStoreUnchanged) {
      const after = sha256File(store);
      if (after !== step.expectStoreUnchanged) {
        return { ok: false, outputs, message: 'store was modified on rejected op' };
      }
    }
  }
  return { ok: true, outputs };
}
