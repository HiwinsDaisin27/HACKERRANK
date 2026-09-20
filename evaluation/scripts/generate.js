/**
 * Single-pass agent evaluation driver.
 *
 * Usage:
 *   1. Point AGENT_SOLUTION_DIR at the directory containing the agent-built grantline (with bin/grantline.js or package bin).
 *   2. npm run generate
 *   3. npm run score
 *
 * This script records metadata under evaluation/proof-of-work/<model-run-id>/.
 * Model runs (Claude Opus 5 / GPT-5.6-sol) should be executed externally with only task/instruction.md provided.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const runId = process.env.MODEL_RUN_ID || 'agent-run';
const outDir = path.join(root, 'evaluation/proof-of-work', runId);
const agentDir = process.env.AGENT_SOLUTION_DIR || path.join(root, 'submission');

fs.mkdirSync(outDir, { recursive: true });

const meta = {
  runId,
  agentDir,
  instruction: path.join(root, 'task/instruction.md'),
  startedAt: new Date().toISOString(),
  notes:
    'After a real single-pass model build, run evaluation/scripts/model-eval-harness.js with transcripts and token counts. Do not use quarantined stub agents.',
};

fs.writeFileSync(path.join(outDir, 'run-meta.json'), JSON.stringify(meta, null, 2));
console.log(`generate: wrote ${path.join(outDir, 'run-meta.json')}`);
console.log('Next: GRANTLINE_BIN="node <agent-bin>" npm run score');
