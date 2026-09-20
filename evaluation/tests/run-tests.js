import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';
import { testCases } from './cases.js';
import { createContext } from './context.js';
import { runGeneratedOracleSuite } from './generated-oracle.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '../..');

function loadScoring() {
  const raw = fs.readFileSync(path.join(root, 'evaluation/scoring.yml'), 'utf8');
  const doc = yaml.parse(raw);
  const weights = doc.weights;
  const sum = Object.values(weights).reduce((a, b) => a + b, 0);
  if (Math.abs(sum - 1.0) > 1e-6) {
    throw new Error(`scoring weights sum to ${sum}, expected 1.0`);
  }
  return weights;
}

function aggregate(results, weights) {
  const byKey = {};
  for (const key of Object.keys(weights)) {
    byKey[key] = { pass: 0, total: 0 };
  }
  for (const r of results) {
    if (!byKey[r.weightKey]) byKey[r.weightKey] = { pass: 0, total: 0 };
    byKey[r.weightKey].total += 1;
    if (r.pass) byKey[r.weightKey].pass += 1;
  }

  const activeKeys = Object.keys(weights).filter((k) => byKey[k]?.total > 0);
  const activeSum = activeKeys.reduce((s, k) => s + weights[k], 0);

  let score = 0;
  for (const key of activeKeys) {
    const w = activeSum ? weights[key] / activeSum : 0;
    const bucket = byKey[key];
    score += w * (bucket.pass / bucket.total);
  }
  return { score, byKey };
}

export function runAllTests() {
  const weights = loadScoring();
  const ctx = createContext();
  const handResults = testCases.map((tc) => {
    let outcome;
    try {
      outcome = tc.run(ctx);
    } catch (e) {
      outcome = { pass: false, message: e.message };
    }
    return {
      id: tc.id,
      weightKey: tc.weightKey,
      pass: !!outcome.pass,
      message: outcome.message,
    };
  });

  let results = handResults;
  let generated = null;
  if (process.env.SKIP_GENERATED !== '1') {
    generated = runGeneratedOracleSuite();
    results = [
      ...handResults,
      {
        id: 'T-GEN-oracle-sessions',
        weightKey: 'generated_oracle',
        pass: generated.pass,
        message: generated.pass
          ? `${generated.passed}/${generated.total} sessions`
          : generated.message,
      },
    ];
  }
  const { score, byKey } = aggregate(results, weights);
  return { results, score, byKey, generated };
}

function main() {
  const { results, score, byKey } = runAllTests();
  const failed = results.filter((r) => !r.pass);
  for (const r of results) {
    const mark = r.pass ? 'PASS' : 'FAIL';
    process.stdout.write(`${mark} ${r.id}${r.message ? ' — ' + r.message : ''}\n`);
  }
  process.stdout.write(`\nScore: ${(score * 100).toFixed(2)}%\n`);
  process.stdout.write(JSON.stringify(byKey, null, 2) + '\n');

  const outPath = process.env.SCORE_OUTPUT;
  if (outPath) {
    fs.writeFileSync(outPath, JSON.stringify({ score, results, byKey }, null, 2));
  }

  const minScore = parseFloat(process.env.MIN_SCORE || '1');
  const maxScore = parseFloat(process.env.MAX_SCORE || '1');
  if (score < minScore - 1e-9 || score > maxScore + 1e-9) {
    process.exit(2);
  }
  if (failed.length && maxScore >= 1) {
    process.exit(1);
  }
  if (maxScore >= 1 && process.env.SKIP_GENERATED === '1') {
    process.stderr.write('error: full verification requires generated oracle (unset SKIP_GENERATED)\n');
    process.exit(1);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main();
}
