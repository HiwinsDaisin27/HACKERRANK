#!/usr/bin/env node

import { main } from '../lib/cli.js';

main().catch((err) => {
  console.error(`grantline: ${err.message}`);
  process.exit(1);
});
