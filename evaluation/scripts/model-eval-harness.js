/**
 * Records a real frontier-model evaluation run (does not invoke models itself).
 *
 * Usage (after agent solution exists):
 *   MODEL_RUN_ID=claude-opus-5-medium \
 *   MODEL_NAME="claude-opus-5-medium-reasoning" \
 *   AGENT_SOLUTION_DIR=submission \
 *   TRANSCRIPT_PATH=/path/to/transcript.md \
 *   INPUT_TOKENS=... OUTPUT_TOKENS=... THINKING_TOKENS=... \
 *   RUNTIME_MS=... BUILD_ERRORS="" \
 *   node evaluation/scripts/model-eval-harness.js
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const runId = process.env.MODEL_RUN_ID;
if (!runId) {
  console.error('MODEL_RUN_ID is required');
  process.exit(1);
}

const outDir = path.join(root, 'evaluation/proof-of-work', runId);
fs.mkdirSync(outDir, { recursive: true });

const agentDir = process.env.AGENT_SOLUTION_DIR || path.join(root, 'submission');
const grantlineBin =
  process.env.GRANTLINE_BIN || `node ${path.join(agentDir, 'bin/grantline.js')}`;

const started = Date.now();
const scoreOut = path.join(outDir, 'score-output.json');
const logOut = path.join(outDir, 'verifier.log');

const scoreRes = spawnSync(process.execPath, ['evaluation/tests/run-tests.js'], {
  cwd: root,
  encoding: 'utf8',
  env: { ...process.env, GRANTLINE_BIN: grantlineBin, SCORE_OUTPUT: scoreOut },
});

fs.writeFileSync(logOut, scoreRes.stdout + (scoreRes.stderr || ''));

const runtimeMs = parseInt(process.env.RUNTIME_MS || String(Date.now() - started), 10);

const meta = {
  runId,
  modelName: process.env.MODEL_NAME || runId,
  instruction: path.join(root, 'task/instruction.md'),
  agentDir,
  grantlineBin,
  startedAt: new Date(started).toISOString(),
  finishedAt: new Date().toISOString(),
  runtimeMs,
  tokens: {
    input: process.env.INPUT_TOKENS ? Number(process.env.INPUT_TOKENS) : null,
    output: process.env.OUTPUT_TOKENS ? Number(process.env.OUTPUT_TOKENS) : null,
    thinking: process.env.THINKING_TOKENS ? Number(process.env.THINKING_TOKENS) : null,
  },
  buildErrors: process.env.BUILD_ERRORS || null,
  outputLimitHit: process.env.OUTPUT_LIMIT_HIT === '1',
  transcriptPath: process.env.TRANSCRIPT_PATH || null,
  scoreExitCode: scoreRes.status,
};

if (process.env.TRANSCRIPT_PATH && fs.existsSync(process.env.TRANSCRIPT_PATH)) {
  fs.copyFileSync(process.env.TRANSCRIPT_PATH, path.join(outDir, 'transcript.md'));
}

fs.writeFileSync(path.join(outDir, 'run-meta.json'), JSON.stringify(meta, null, 2));

if (fs.existsSync(scoreOut)) {
  const score = JSON.parse(fs.readFileSync(scoreOut, 'utf8'));
  console.log(`Model eval recorded: ${(score.score * 100).toFixed(2)}% → ${outDir}`);
} else {
  console.log(`Model eval recorded (no score — build failure?): ${outDir}`);
}

process.exit(scoreRes.status ?? 1);
