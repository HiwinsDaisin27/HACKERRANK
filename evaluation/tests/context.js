import fs from 'fs';
import { runGrantline, tempStorePath, sha256File } from '../lib/harness.js';

export function createContext() {
  return {
    freshStore() {
      const p = tempStorePath();
      runGrantline(['init', '--store', p]);
      return p;
    },
    gl(args, store) {
      const [cmd, ...rest] = args;
      return runGrantline([cmd, '--store', store, ...rest]);
    },
    hash(store) {
      return sha256File(store);
    },
    setupBasicOrg(store) {
      this.gl(['add-principal', '--id', 'alice'], store);
      this.gl(['add-group', '--id', 'org'], store);
      this.gl(['add-group', '--id', 'leaf'], store);
      this.gl(['add-group-member', '--group', 'org', '--member', 'leaf'], store);
      this.gl(['add-group-member', '--group', 'leaf', '--member', 'alice'], store);
    },
    pass() {
      return { pass: true };
    },
    fail(message) {
      return { pass: false, message };
    },
    tamper(store, mutator) {
      const data = JSON.parse(fs.readFileSync(store, 'utf8'));
      mutator(data);
      fs.writeFileSync(store, JSON.stringify(data, null, 2) + '\n');
    },
  };
}
