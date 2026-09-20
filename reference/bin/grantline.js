#!/usr/bin/env node
import {
  cmdInit,
  cmdAddPrincipal,
  cmdAddGroup,
  cmdAddGroupMember,
  cmdRemoveGroupMember,
  cmdGrant,
  cmdDeny,
  cmdRevoke,
  cmdQuery,
  cmdExplain,
  cmdMoveResource,
} from '../lib/commands.js';

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function requireFlag(flags, name) {
  if (flags[name] === undefined || flags[name] === true) {
    throw new Error(`missing --${name}`);
  }
  return flags[name];
}

function usage() {
  process.stderr.write(`Usage: grantline <command> [options]\n`);
}

async function main() {
  const { positional, flags } = parseArgs(process.argv.slice(2));
  const cmd = positional[0];
  if (!cmd) {
    usage();
    process.exit(1);
  }

  try {
    switch (cmd) {
      case 'init': {
        const store = requireFlag(flags, 'store');
        cmdInit(store);
        break;
      }
      case 'add-principal': {
        cmdAddPrincipal(requireFlag(flags, 'store'), requireFlag(flags, 'id'));
        break;
      }
      case 'add-group': {
        cmdAddGroup(requireFlag(flags, 'store'), requireFlag(flags, 'id'));
        break;
      }
      case 'add-group-member': {
        cmdAddGroupMember(
          requireFlag(flags, 'store'),
          requireFlag(flags, 'group'),
          requireFlag(flags, 'member')
        );
        break;
      }
      case 'remove-group-member': {
        cmdRemoveGroupMember(
          requireFlag(flags, 'store'),
          requireFlag(flags, 'group'),
          requireFlag(flags, 'member')
        );
        break;
      }
      case 'grant': {
        cmdGrant(requireFlag(flags, 'store'), {
          principalOrGroup: requireFlag(flags, 'principal-or-group'),
          resource: requireFlag(flags, 'resource'),
          action: requireFlag(flags, 'action'),
          validFrom: flags['valid-from'],
          validUntil: flags['valid-until'],
        });
        break;
      }
      case 'deny': {
        cmdDeny(requireFlag(flags, 'store'), {
          principalOrGroup: requireFlag(flags, 'principal-or-group'),
          resource: requireFlag(flags, 'resource'),
          action: requireFlag(flags, 'action'),
          validFrom: flags['valid-from'],
          validUntil: flags['valid-until'],
        });
        break;
      }
      case 'revoke': {
        cmdRevoke(requireFlag(flags, 'store'), requireFlag(flags, 'rule-id'));
        break;
      }
      case 'query': {
        const out = cmdQuery(
          requireFlag(flags, 'store'),
          requireFlag(flags, 'principal'),
          requireFlag(flags, 'resource'),
          requireFlag(flags, 'action'),
          flags.at
        );
        process.stdout.write(out + '\n');
        break;
      }
      case 'explain': {
        const out = cmdExplain(
          requireFlag(flags, 'store'),
          requireFlag(flags, 'principal'),
          requireFlag(flags, 'resource'),
          requireFlag(flags, 'action'),
          flags.at
        );
        process.stdout.write(out);
        break;
      }
      case 'move-resource': {
        cmdMoveResource(
          requireFlag(flags, 'store'),
          requireFlag(flags, 'from'),
          requireFlag(flags, 'to')
        );
        break;
      }
      default:
        throw new Error(`unknown command: ${cmd}`);
    }
    process.exit(0);
  } catch (e) {
    if (e.code === 'STORE_CORRUPT') {
      process.stderr.write(`grantline: store corruption detected: ${e.message}\n`);
      process.exit(e.exitCode ?? 3);
    }
    process.stderr.write(`grantline: ${e.message}\n`);
    process.exit(1);
  }
}

main();
