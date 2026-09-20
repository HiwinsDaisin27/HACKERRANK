import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const outDir = process.argv[2];
const grantlineBin = process.argv[3];

if (!outDir || !grantlineBin) {
  console.error('Usage: node record-score.js <output-dir> <GRANTLINE_BIN>');
  process.exit(1);
}

fs.mkdirSync(outDir, { recursive: true });
const scoreFile = path.join(outDir, 'score-output.json');
const logFile = path.join(outDir, 'verifier.log');

const res = spawnSync(process.execPath, ['evaluation/tests/run-tests.js'], {
  cwd: root,
  encoding: 'utf8',
  env: { ...process.env, GRANTLINE_BIN: grantlineBin, SCORE_OUTPUT: scoreFile },
});

fs.writeFileSync(logFile, res.stdout + (res.stderr || ''));
const score = JSON.parse(fs.readFileSync(scoreFile, 'utf8'));
console.log(`Recorded ${(score.score * 100).toFixed(2)}% to ${outDir}`);
process.exit(res.status ?? 0);
