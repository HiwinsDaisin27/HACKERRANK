#!/usr/bin/env node
/**
 * model-eval-harness.js — Frontier model evaluation driver and result recorder.
 *
 * Supports parsing raw single-pass model response into files, executing test verifier,
 * and generating complete evaluation artifacts:
 *   - generated-solution/ (on-disk parsed files)
 *   - metadata.json & run-meta.json (token counts, timing, execution metadata)
 *   - run.log & verifier.log (complete verifier stdout/stderr)
 *   - score-output.json (raw score & per-check result array)
 *   - transcript.md & raw-response.txt (full model output)
 *   - eval-summary.md (markdown report with per-category breakdown and failure write-up)
 *
 * Usage:
 *   MODEL_RUN_ID=claude-opus-5-medium \
 *   MODEL_NAME="Claude Opus 5 (medium reasoning)" \
 *   RESPONSE_FILE=/path/to/raw-response.txt \
 *   INPUT_TOKENS=1420 OUTPUT_TOKENS=3890 THINKING_TOKENS=2100 \
 *   RUNTIME_MS=45200 \
 *   node evaluation/scripts/model-eval-harness.js
 *
 * DRY RUN mode (safely writes to evaluation/_quarantine/dry-run-eval/):
 *   DRY_RUN=1 RESPONSE_FILE=/path/to/raw-response.txt node evaluation/scripts/model-eval-harness.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const isDryRun = process.env.DRY_RUN === '1';
const runId = process.env.MODEL_RUN_ID || (isDryRun ? 'dry-run-test' : null);

if (!runId && !isDryRun) {
  console.error('Error: MODEL_RUN_ID is required (e.g. claude-opus-5-medium, gpt-5.6-sol-medium)');
  process.exit(1);
}

// Output directory
const outDir = isDryRun
  ? path.join(root, 'evaluation/_quarantine/dry-run-eval')
  : path.join(root, 'evaluation/proof-of-work', runId);

fs.mkdirSync(outDir, { recursive: true });

// Parse response file if provided
const responseFile = process.env.RESPONSE_FILE;
let solutionDir = process.env.AGENT_SOLUTION_DIR;

if (responseFile && fs.existsSync(responseFile)) {
  const targetSolutionDir = path.join(outDir, 'generated-solution');
  fs.mkdirSync(targetSolutionDir, { recursive: true });

  const rawText = fs.readFileSync(responseFile, 'utf8');

  // Copy raw response / transcript
  fs.writeFileSync(path.join(outDir, 'raw-response.txt'), rawText, 'utf8');
  fs.writeFileSync(path.join(outDir, 'transcript.md'), `# Raw Model Response\n\n\`\`\`\n${rawText}\n\`\`\`\n`, 'utf8');

  // Parse files: supports ===FILE: path=== ... ===END FILE=== as well as markdown fences
  const FILE_START = /^===FILE:\s*(.+?)\s*===\s*$/m;
  const FILE_END = /^===END FILE===\s*$/m;

  const files = [];
  let remaining = rawText;

  while (true) {
    const startMatch = FILE_START.exec(remaining);
    if (!startMatch) break;

    const filePath = startMatch[1].trim();
    const afterHeader = remaining.slice(startMatch.index + startMatch[0].length + 1);
    const endMatch = FILE_END.exec(afterHeader);

    if (!endMatch) break;

    let content = afterHeader.slice(0, endMatch.index);
    if (content.startsWith('\n')) content = content.slice(1);

    files.push({ path: filePath, content });
    remaining = afterHeader.slice(endMatch.index + endMatch[0].length);
  }

  if (files.length > 0) {
    for (const f of files) {
      const dest = path.join(targetSolutionDir, f.path);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, f.content, 'utf8');
    }
    console.log(`Parsed ${files.length} file(s) into: ${targetSolutionDir}`);
  } else {
    console.warn('Warning: No ===FILE: path=== blocks found in RESPONSE_FILE');
  }

  solutionDir = targetSolutionDir;
}

if (!solutionDir) {
  solutionDir = path.join(outDir, 'generated-solution');
}

// Determine entrypoint
let grantlineBin = process.env.GRANTLINE_BIN;
if (!grantlineBin) {
  if (fs.existsSync(path.join(solutionDir, 'package.json'))) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(solutionDir, 'package.json'), 'utf8'));
      if (pkg.bin) {
        const binRel = typeof pkg.bin === 'string' ? pkg.bin : Object.values(pkg.bin)[0];
        if (binRel && fs.existsSync(path.join(solutionDir, binRel))) {
          grantlineBin = `node ${path.join(solutionDir, binRel)}`;
        }
      } else if (pkg.main && fs.existsSync(path.join(solutionDir, pkg.main))) {
        grantlineBin = `node ${path.join(solutionDir, pkg.main)}`;
      }
    } catch (_) {}
  }
  if (!grantlineBin) {
    if (fs.existsSync(path.join(solutionDir, 'bin/grantline.js'))) {
      grantlineBin = `node ${path.join(solutionDir, 'bin/grantline.js')}`;
    } else if (fs.existsSync(path.join(solutionDir, 'grantline.js'))) {
      grantlineBin = `node ${path.join(solutionDir, 'grantline.js')}`;
    } else {
      grantlineBin = `node ${path.join(solutionDir, 'bin/grantline.js')}`;
    }
  }
}

// Run verifier
const started = Date.now();
const scoreOut = path.join(outDir, 'score-output.json');
const logOut = path.join(outDir, 'verifier.log');
const runLogOut = path.join(outDir, 'run.log');

console.log(`Running verifier against: ${grantlineBin}`);
const scoreRes = spawnSync(process.execPath, ['evaluation/tests/run-tests.js'], {
  cwd: root,
  encoding: 'utf8',
  env: { ...process.env, GRANTLINE_BIN: grantlineBin, SCORE_OUTPUT: scoreOut },
});

const fullLog = scoreRes.stdout + (scoreRes.stderr || '');
fs.writeFileSync(logOut, fullLog, 'utf8');
fs.writeFileSync(runLogOut, fullLog, 'utf8');

const runtimeMs = parseInt(process.env.RUNTIME_MS || String(Date.now() - started), 10);

const meta = {
  runId: isDryRun ? 'dry-run-test' : runId,
  modelName: process.env.MODEL_NAME || runId,
  isDryRun,
  instruction: path.join(root, 'task/instruction.md'),
  solutionDir,
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
  scoreExitCode: scoreRes.status,
};

fs.writeFileSync(path.join(outDir, 'metadata.json'), JSON.stringify(meta, null, 2), 'utf8');
fs.writeFileSync(path.join(outDir, 'run-meta.json'), JSON.stringify(meta, null, 2), 'utf8');

// Generate eval-summary.md
let scoreData = { score: 0, results: [], byKey: {} };
if (fs.existsSync(scoreOut)) {
  try {
    scoreData = JSON.parse(fs.readFileSync(scoreOut, 'utf8'));
  } catch (e) {
    console.error('Failed to parse score output:', e.message);
  }
}

const failedTests = scoreData.results.filter((r) => !r.pass);
const passedTests = scoreData.results.filter((r) => r.pass);

// Categorize failures
const failureCategories = {};
for (const f of failedTests) {
  const cat = f.weightKey || 'other';
  if (!failureCategories[cat]) failureCategories[cat] = [];
  failureCategories[cat].push(f);
}

let summaryMd = `# Model Evaluation Summary: ${meta.modelName}\n\n`;
summaryMd += `- **Run ID:** \`${meta.runId}\`\n`;
summaryMd += `- **Date:** ${meta.finishedAt}\n`;
summaryMd += `- **Wall-clock Duration:** ${meta.runtimeMs} ms\n`;
summaryMd += `- **Token Usage:** Input: ${meta.tokens.input ?? 'N/A'}, Output: ${meta.tokens.output ?? 'N/A'}, Thinking: ${meta.tokens.thinking ?? 'N/A'}\n`;
summaryMd += `- **Overall Score:** **${(scoreData.score * 100).toFixed(2)}%**\n`;
summaryMd += `- **Tests Passed:** ${passedTests.length} / ${scoreData.results.length}\n\n`;

summaryMd += `## Category Breakdown\n\n`;
summaryMd += `| Category | Total Checks | Passed | Pass Rate |\n`;
summaryMd += `| :--- | :---: | :---: | :---: |\n`;
for (const [key, val] of Object.entries(scoreData.byKey || {})) {
  const rate = val.total > 0 ? ((val.pass / val.total) * 100).toFixed(1) + '%' : 'N/A';
  summaryMd += `| \`${key}\` | ${val.total} | ${val.pass} | ${rate} |\n`;
}

summaryMd += `\n## Per-Check Details\n\n`;
summaryMd += `| Test ID | Category | Status | Details |\n`;
summaryMd += `| :--- | :--- | :---: | :--- |\n`;
for (const r of scoreData.results) {
  const status = r.pass ? '✅ PASS' : '❌ FAIL';
  const msg = r.message ? `\`${r.message}\`` : '—';
  summaryMd += `| \`${r.id}\` | \`${r.weightKey}\` | ${status} | ${msg} |\n`;
}

summaryMd += `\n## Failure Category Analysis\n\n`;
if (failedTests.length === 0) {
  summaryMd += `No failures detected. All checks passed.\n`;
} else {
  for (const [cat, tests] of Object.entries(failureCategories)) {
    summaryMd += `### Category: \`${cat}\` (${tests.length} failure${tests.length > 1 ? 's' : ''})\n`;
    for (const t of tests) {
      summaryMd += `- **${t.id}:** ${t.message || 'Failed without specific message'}\n`;
    }
    summaryMd += `\n`;
  }
}

fs.writeFileSync(path.join(outDir, 'eval-summary.md'), summaryMd, 'utf8');

console.log(`\nEvaluation complete.`);
console.log(`Score: ${(scoreData.score * 100).toFixed(2)}%`);
console.log(`Artifacts written to: ${outDir}`);
console.log(`  - eval-summary.md`);
console.log(`  - metadata.json / run-meta.json`);
console.log(`  - score-output.json`);
console.log(`  - run.log / verifier.log`);
if (fs.existsSync(path.join(outDir, 'transcript.md'))) {
  console.log(`  - transcript.md / raw-response.txt`);
}

process.exit(scoreRes.status ?? (failedTests.length > 0 ? 1 : 0));
