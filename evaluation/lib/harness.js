import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import crypto from 'crypto';

export function resolveCandidateEntrypoint(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return null;
  const pkgPath = path.join(dirPath, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg.bin) {
        const binRel = typeof pkg.bin === 'string' ? pkg.bin : (pkg.bin.grantline || Object.values(pkg.bin)[0]);
        if (binRel && fs.existsSync(path.join(dirPath, binRel))) {
          return `node ${path.resolve(dirPath, binRel)}`;
        }
      }
    } catch (_) {}
  }
  const standardBin = path.join(dirPath, 'bin', 'grantline.js');
  if (fs.existsSync(standardBin)) {
    return `node ${path.resolve(standardBin)}`;
  }
  const rootBin = path.join(dirPath, 'grantline.js');
  if (fs.existsSync(rootBin)) {
    return `node ${path.resolve(rootBin)}`;
  }
  return null;
}

export function resolveGrantlineBinSpec(fromEnv) {
  if (!fromEnv) return null;
  const trimmed = fromEnv.trim();
  const parts = trimmed.split(/\s+/).filter(Boolean);
  let target = parts.length > 1 && parts[0] === 'node' ? parts.slice(1).join(' ') : trimmed;
  target = target.replace(/^['"]|['"]$/g, '');

  if (fs.existsSync(target)) {
    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
      const resolved = resolveCandidateEntrypoint(target);
      if (resolved) return resolved;
    } else if (stat.isFile()) {
      // If pointed to a file e.g. src/grantline.js, check if enclosing candidate dir defines package.json bin
      const dir = path.dirname(target);
      const parentDir = path.dirname(dir);
      const parentPkg = path.join(parentDir, 'package.json');
      if (fs.existsSync(parentPkg)) {
        try {
          const pkg = JSON.parse(fs.readFileSync(parentPkg, 'utf8'));
          if (pkg.bin) {
            const binRel = typeof pkg.bin === 'string' ? pkg.bin : (pkg.bin.grantline || Object.values(pkg.bin)[0]);
            const candidateBin = path.join(parentDir, binRel);
            if (fs.existsSync(candidateBin) && path.resolve(candidateBin) !== path.resolve(target)) {
              return `node ${path.resolve(candidateBin)}`;
            }
          }
        } catch (_) {}
      }
    }
  }
  return fromEnv;
}

export function grantlineBin() {
  const fromEnv = process.env.GRANTLINE_BIN;
  if (fromEnv) {
    const resolved = resolveGrantlineBinSpec(fromEnv);
    if (resolved) return resolved;
    return fromEnv;
  }
  if (process.env.AGENT_SOLUTION_DIR) {
    const resolved = resolveCandidateEntrypoint(process.env.AGENT_SOLUTION_DIR);
    if (resolved) return resolved;
  }
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
    timeout: opts.timeout || 10000,
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
