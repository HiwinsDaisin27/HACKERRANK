import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';
import { runGeneratedOracleSuite } from '../tests/generated-oracle.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const reference = path.join(root, 'reference');
const mutantsRoot = path.join(root, 'evaluation/proof-of-work/mutants');

const MUTANTS = [
  'mutant-1-precedence-order',
  'mutant-2-shallow-cycle',
  'mutant-3-stale-revocation-cache',
  'mutant-4-non-atomic-cycle',
  'mutant-5-no-corruption-check',
  'mutant-6-ignore-time-bounds',
];

const ORACLE = `node ${path.join(root, 'reference/bin/grantline.js')}`;
const GEN_SESSIONS = parseInt(process.env.MUTANT_GENERATED_SESSIONS || '50', 10);

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

function runHandTests(grantlineBin) {
  const res = spawnSync(process.execPath, ['evaluation/tests/run-tests.js'], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      GRANTLINE_BIN: grantlineBin,
      SKIP_GENERATED: '1',
      MIN_SCORE: '0',
      MAX_SCORE: '0.999',
    },
  });
  const m = res.stdout.match(/Score: ([0-9.]+)%/);
  const score = m ? parseFloat(m[1]) / 100 : 1;
  return { score, stdout: res.stdout, status: res.status };
}

function runGeneratedAgainstOracle(grantlineBin) {
  const prevBin = process.env.GRANTLINE_BIN;
  const prevOracle = process.env.GRANTLINE_ORACLE_BIN;
  process.env.GRANTLINE_BIN = grantlineBin;
  process.env.GRANTLINE_ORACLE_BIN = ORACLE;
  const gen = runGeneratedOracleSuite({ sessions: GEN_SESSIONS });
  process.env.GRANTLINE_BIN = prevBin;
  process.env.GRANTLINE_ORACLE_BIN = prevOracle;
  return gen;
}

function main() {
  const results = [];
  for (const name of MUTANTS) {
    const overlay = path.join(mutantsRoot, name);
    if (!fs.existsSync(overlay)) {
      console.error(`Missing mutant directory: ${overlay}`);
      process.exit(1);
    }
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `grantline-${name}-`));
    copyDir(reference, tmp);
    for (const rel of listFilesRecursive(overlay)) {
      const relFromMutant = path.relative(overlay, rel);
      fs.mkdirSync(path.dirname(path.join(tmp, relFromMutant)), { recursive: true });
      fs.copyFileSync(rel, path.join(tmp, relFromMutant));
    }
    const bin = `node ${path.join(tmp, 'bin/grantline.js')}`;

    const hand = runHandTests(bin);
    const gen = runGeneratedAgainstOracle(bin);
    const caught = !gen.pass || hand.score < 0.999;
    results.push({
      name,
      handScore: hand.score,
      generatedPassed: gen.pass,
      generatedDetail: `${gen.passed}/${gen.total}`,
      caught,
    });
    console.log(`\n=== ${name} hand=${(hand.score * 100).toFixed(1)}% gen=${gen.passed}/${gen.total} caught=${caught} ===`);
    console.log(hand.stdout);
    if (!caught) {
      console.error(`Mutant not caught: ${name}`);
      process.exit(1);
    }
  }
  const logPath = path.join(mutantsRoot, 'mutant-run-summary.json');
  fs.writeFileSync(logPath, JSON.stringify(results, null, 2));
  console.log('\nAll mutants caught (hand-written and/or generated oracle).');
}

function listFilesRecursive(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFilesRecursive(p));
    else out.push(p);
  }
  return out;
}

main();
