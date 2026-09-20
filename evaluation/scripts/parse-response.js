#!/usr/bin/env node
/**
 * parse-response.js — Parse a model's raw text response into files on disk.
 *
 * The model is prompted to wrap every file it writes using the boundary marker:
 *
 *   ===FILE: relative/path/to/file.js===
 *   ...file content...
 *   ===END FILE===
 *
 * Usage:
 *   MODEL_RUN_ID=claude-opus-5-medium \
 *   RESPONSE_FILE=/path/to/raw-response.txt \
 *   node evaluation/scripts/parse-response.js
 *
 * Output: evaluation/proof-of-work/<MODEL_RUN_ID>/generated-solution/
 *
 * DRY-RUN mode (never touches proof-of-work/):
 *   DRY_RUN=1 RESPONSE_FILE=/path/to/response.txt node evaluation/scripts/parse-response.js
 *   Output: evaluation/_quarantine/dry-run-parse-test/
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const isDryRun = process.env.DRY_RUN === '1';
const runId = process.env.MODEL_RUN_ID;
const responseFile = process.env.RESPONSE_FILE;

if (!responseFile) {
  console.error('Error: RESPONSE_FILE environment variable is required.');
  process.exit(1);
}
if (!isDryRun && !runId) {
  console.error('Error: MODEL_RUN_ID is required (or set DRY_RUN=1 for a test run).');
  process.exit(1);
}
if (!fs.existsSync(responseFile)) {
  console.error(`Error: RESPONSE_FILE not found: ${responseFile}`);
  process.exit(1);
}

// Output directory
let outDir;
if (isDryRun) {
  outDir = path.join(root, 'evaluation/_quarantine/dry-run-parse-test/generated-solution');
  console.log('[DRY RUN] Output:', outDir);
  console.log('[DRY RUN] Will NOT write to proof-of-work/');
} else {
  outDir = path.join(root, 'evaluation/proof-of-work', runId, 'generated-solution');
}

// Validate model run ID names
const VALID_RUN_IDS = ['claude-opus-5-medium', 'gpt-5.6-sol-medium'];
if (!isDryRun && !VALID_RUN_IDS.includes(runId)) {
  console.warn(`Warning: MODEL_RUN_ID "${runId}" is not a known model ID (${VALID_RUN_IDS.join(', ')})`);
}

// Parse ===FILE: path=== ... ===END FILE=== blocks
const responseText = fs.readFileSync(responseFile, 'utf8');
const FILE_START = /^===FILE:\s*(.+?)\s*===\s*$/m;
const FILE_END = /^===END FILE===\s*$/m;

const files = [];
const parseErrors = [];
let remaining = responseText;

while (true) {
  const startMatch = FILE_START.exec(remaining);
  if (!startMatch) break;

  const filePath = startMatch[1].trim();
  const afterHeader = remaining.slice(startMatch.index + startMatch[0].length + 1);
  const endMatch = FILE_END.exec(afterHeader);

  if (!endMatch) {
    parseErrors.push(`Unclosed block for: ${filePath} — missing ===END FILE===`);
    break;
  }

  let content = afterHeader.slice(0, endMatch.index);
  if (content.startsWith('\n')) content = content.slice(1);

  files.push({ path: filePath, content });
  remaining = afterHeader.slice(endMatch.index + endMatch[0].length);
}

if (files.length === 0) {
  console.error('Error: No ===FILE: ...=== blocks found in response.');
  console.error('Model response must use:');
  console.error('  ===FILE: bin/grantline.js===');
  console.error('  ...content...');
  console.error('  ===END FILE===');
  if (parseErrors.length) console.error('Parse errors:', parseErrors);
  process.exit(1);
}

// Validate no path traversal
for (const f of files) {
  const resolved = path.resolve(outDir, f.path);
  if (!resolved.startsWith(outDir + path.sep) && resolved !== outDir) {
    console.error(`Error: Path traversal blocked: ${f.path}`);
    process.exit(1);
  }
}

// Write files
fs.mkdirSync(outDir, { recursive: true });
const written = [];
for (const f of files) {
  const dest = path.join(outDir, f.path);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, f.content, 'utf8');
  written.push(f.path);
  console.log('  wrote:', f.path, `(${f.content.length} bytes)`);
}

// Check entrypoint
const entrypoint = path.join(outDir, 'bin', 'grantline.js');
if (!fs.existsSync(entrypoint)) {
  console.warn('Warning: bin/grantline.js not found. Files written:', written.join(', '));
}

// Write parse summary
const summary = {
  runId: isDryRun ? 'DRY_RUN' : runId,
  isDryRun,
  responseFile,
  parsedAt: new Date().toISOString(),
  filesWritten: written,
  parseErrors,
  entrypointPath: entrypoint,
  entrypointExists: fs.existsSync(entrypoint),
};
const summaryDest = isDryRun
  ? path.join(root, 'evaluation/_quarantine/dry-run-parse-test/parse-summary.json')
  : path.join(root, 'evaluation/proof-of-work', runId, 'parse-summary.json');
fs.mkdirSync(path.dirname(summaryDest), { recursive: true });
fs.writeFileSync(summaryDest, JSON.stringify(summary, null, 2));

console.log(`\nParsed ${files.length} file(s) → ${outDir}`);
if (parseErrors.length) console.warn('Parse errors:', parseErrors);

if (isDryRun) {
  console.log('[DRY RUN] Complete. Check evaluation/_quarantine/dry-run-parse-test/ — safe to delete.');
} else {
  console.log(`\nNext: score the solution:`);
  console.log(`  GRANTLINE_BIN="node ${entrypoint}" npm run score`);
  console.log(`Or record full model eval:`);
  console.log(`  MODEL_RUN_ID=${runId} GRANTLINE_BIN="node ${entrypoint}" \\ `);
  console.log(`    node evaluation/scripts/model-eval-harness.js`);
}
