export const testCases = [
  {
    id: 'T001-precedence-narrow-allow',
    weightKey: 'precedence_composed',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.setupBasicOrg(s);
      ctx.gl(['deny', '--principal-or-group', 'org', '--resource', '/app', '--action', 'read'], s);
      ctx.gl(['grant', '--principal-or-group', 'leaf', '--resource', '/app/secret', '--action', 'read'], s);
      const q = ctx.gl(['query', '--principal', 'alice', '--resource', '/app/secret/doc', '--action', 'read'], s);
      if (q.stdout !== 'ALLOW\n') return ctx.fail('narrow allow must beat broad deny');
      return ctx.pass();
    },
  },
  {
    id: 'T002-precedence-deny-same-specificity',
    weightKey: 'precedence_composed',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.setupBasicOrg(s);
      ctx.gl(['grant', '--principal-or-group', 'alice', '--resource', '/data', '--action', 'write'], s);
      ctx.gl(['deny', '--principal-or-group', 'org', '--resource', '/data', '--action', 'write'], s);
      const q = ctx.gl(['query', '--principal', 'alice', '--resource', '/data/x', '--action', 'write'], s);
      if (q.stdout !== 'DENY\n') return ctx.fail('deny wins at max specificity');
      return ctx.pass();
    },
  },
  {
    id: 'T003-diamond-explain-path',
    weightKey: 'group_nesting_composed',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-principal', '--id', 'p1'], s);
      for (const id of ['top', 'left', 'right', 'bottom']) ctx.gl(['add-group', '--id', id], s);
      ctx.gl(['add-group-member', '--group', 'left', '--member', 'bottom'], s);
      ctx.gl(['add-group-member', '--group', 'right', '--member', 'bottom'], s);
      ctx.gl(['add-group-member', '--group', 'top', '--member', 'left'], s);
      ctx.gl(['add-group-member', '--group', 'top', '--member', 'right'], s);
      ctx.gl(['add-group-member', '--group', 'bottom', '--member', 'p1'], s);
      ctx.gl(['grant', '--principal-or-group', 'top', '--resource', '/x', '--action', 'read'], s);
      const ex = ctx.gl(
        ['explain', '--principal', 'p1', '--resource', '/x/y', '--action', 'read', '--at', '2025-01-01T00:00:00Z'],
        s
      );
      if (ex.stdout !== 'DECISION: ALLOW\nMATCH: rule_id=rule-1 effect=allow action=read resource=/x specificity=1 target_type=group target_id=top membership_path=top>left>bottom\n') {
        return ctx.fail(`unexpected explain:\n${ex.stdout}`);
      }
      return ctx.pass();
    },
  },
  {
    id: 'T004-cycle-three-node',
    weightKey: 'cycle_atomicity',
    run(ctx) {
      const s = ctx.freshStore();
      for (const id of ['a', 'b', 'c']) ctx.gl(['add-group', '--id', id], s);
      ctx.gl(['add-group-member', '--group', 'a', '--member', 'b'], s);
      ctx.gl(['add-group-member', '--group', 'b', '--member', 'c'], s);
      const h = ctx.hash(s);
      const res = ctx.gl(['add-group-member', '--group', 'c', '--member', 'a'], s);
      if (res.status === 0) return ctx.fail('must reject 3-cycle');
      if (ctx.hash(s) !== h) return ctx.fail('store must be unchanged');
      return ctx.pass();
    },
  },
  {
    id: 'T005-cycle-two-node',
    weightKey: 'cycle_atomicity',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-group', '--id', 'x'], s);
      ctx.gl(['add-group', '--id', 'y'], s);
      ctx.gl(['add-group-member', '--group', 'x', '--member', 'y'], s);
      const h = ctx.hash(s);
      const res = ctx.gl(['add-group-member', '--group', 'y', '--member', 'x'], s);
      if (res.status === 0) return ctx.fail('must reject 2-cycle');
      if (ctx.hash(s) !== h) return ctx.fail('store unchanged');
      return ctx.pass();
    },
  },
  {
    id: 'T006-revoke-cascades-deep',
    weightKey: 'revocation_composed',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-principal', '--id', 'u'], s);
      ctx.gl(['add-group', '--id', 'g1'], s);
      ctx.gl(['add-group', '--id', 'g2'], s);
      ctx.gl(['add-group-member', '--group', 'g1', '--member', 'g2'], s);
      ctx.gl(['add-group-member', '--group', 'g2', '--member', 'u'], s);
      ctx.gl(['grant', '--principal-or-group', 'g1', '--resource', '/docs', '--action', 'read'], s);
      if (ctx.gl(['query', '--principal', 'u', '--resource', '/docs/a', '--action', 'read'], s).stdout !== 'ALLOW\n') {
        return ctx.fail('pre-revoke allow');
      }
      ctx.gl(['revoke', '--rule-id', 'rule-1'], s);
      const after = ctx.gl(['query', '--principal', 'u', '--resource', '/docs/a', '--action', 'read'], s);
      if (after.stdout !== 'DENY\n') return ctx.fail('post-revoke must deny nested principal');
      return ctx.pass();
    },
  },
  {
    id: 'T007-corruption-cycle-on-load',
    weightKey: 'tamper_detection',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-principal', '--id', 'u'], s);
      ctx.gl(['add-group', '--id', 'g1'], s);
      ctx.gl(['add-group', '--id', 'g2'], s);
      ctx.gl(['add-group-member', '--group', 'g1', '--member', 'g2'], s);
      ctx.tamper(s, (d) => {
        d.groups.g2.members.push('g1');
      });
      const res = ctx.gl(['query', '--principal', 'u', '--resource', '/', '--action', 'read'], s);
      if (res.status !== 3) return ctx.fail(`expected exit 3, got ${res.status}`);
      if (!res.stderr.startsWith('grantline: store corruption detected:')) {
        return ctx.fail('corruption stderr format');
      }
      return ctx.pass();
    },
  },
  {
    id: 'T008-corruption-dangling-member',
    weightKey: 'tamper_detection',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-group', '--id', 'g1'], s);
      ctx.tamper(s, (d) => {
        d.groups.g1.members.push('missing');
      });
      const res = ctx.gl(['add-principal', '--id', 'a'], s);
      if (res.status !== 3) return ctx.fail('must refuse mutated store');
      return ctx.pass();
    },
  },
  {
    id: 'T009-time-bound-expired',
    weightKey: 'time_bounds_composed',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-principal', '--id', 'u'], s);
      ctx.gl(
        [
          'grant',
          '--principal-or-group',
          'u',
          '--resource',
          '/t',
          '--action',
          'read',
          '--valid-until',
          '2025-06-01T00:00:00Z',
        ],
        s
      );
      const q = ctx.gl(
        ['query', '--principal', 'u', '--resource', '/t/a', '--action', 'read', '--at', '2025-06-01T00:00:00Z'],
        s
      );
      if (q.stdout !== 'DENY\n') return ctx.fail('expired rule must not apply at valid_until');
      const q2 = ctx.gl(
        ['query', '--principal', 'u', '--resource', '/t/a', '--action', 'read', '--at', '2025-05-31T23:59:59Z'],
        s
      );
      if (q2.stdout !== 'ALLOW\n') return ctx.fail('rule valid before expiry');
      return ctx.pass();
    },
  },
  {
    id: 'T010-time-with-nested-group',
    weightKey: 'time_bounds_composed',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-principal', '--id', 'u'], s);
      ctx.gl(['add-group', '--id', 'g'], s);
      ctx.gl(['add-group-member', '--group', 'g', '--member', 'u'], s);
      ctx.gl(
        [
          'grant',
          '--principal-or-group',
          'g',
          '--resource',
          '/r',
          '--action',
          'admin',
          '--valid-from',
          '2025-01-01T00:00:00Z',
          '--valid-until',
          '2025-02-01T00:00:00Z',
        ],
        s
      );
      const inside = ctx.gl(
        ['query', '--principal', 'u', '--resource', '/r/x', '--action', 'admin', '--at', '2025-01-15T00:00:00Z'],
        s
      );
      const outside = ctx.gl(
        ['query', '--principal', 'u', '--resource', '/r/x', '--action', 'admin', '--at', '2025-03-01T00:00:00Z'],
        s
      );
      if (inside.stdout !== 'ALLOW\n' || outside.stdout !== 'DENY\n') {
        return ctx.fail('time window with group inheritance');
      }
      return ctx.pass();
    },
  },
  {
    id: 'T011-move-resource-prefix',
    weightKey: 'resource_move',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-principal', '--id', 'u'], s);
      ctx.gl(['grant', '--principal-or-group', 'u', '--resource', '/old/deep', '--action', 'write'], s);
      ctx.gl(['move-resource', '--from', '/old', '--to', '/new'], s);
      const q = ctx.gl(['query', '--principal', 'u', '--resource', '/new/deep/file', '--action', 'write'], s);
      if (q.stdout !== 'ALLOW\n') return ctx.fail('moved prefix should match');
      const q2 = ctx.gl(['query', '--principal', 'u', '--resource', '/old/deep/file', '--action', 'write'], s);
      if (q2.stdout !== 'DENY\n') return ctx.fail('old path should not match');
      return ctx.pass();
    },
  },
  {
    id: 'T012-explain-default-deny',
    weightKey: 'explain_format',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-principal', '--id', 'u'], s);
      const ex = ctx.gl(['explain', '--principal', 'u', '--resource', '/nope', '--action', 'read'], s);
      if (!ex.stdout.startsWith('DECISION: DENY\nMATCH: none\n')) {
        return ctx.fail('default deny explain');
      }
      return ctx.pass();
    },
  },
  {
    id: 'T013-explain-multi-deny-sorted',
    weightKey: 'explain_format',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-principal', '--id', 'u'], s);
      ctx.gl(['deny', '--principal-or-group', 'u', '--resource', '/z', '--action', 'read'], s);
      ctx.gl(['deny', '--principal-or-group', 'u', '--resource', '/z', '--action', 'read'], s);
      const ex = ctx.gl(['explain', '--principal', 'u', '--resource', '/z/k', '--action', 'read'], s);
      const lines = ex.stdout.trim().split('\n');
      if (lines[0] !== 'DECISION: DENY') return ctx.fail('decision line');
      const matchLines = lines.slice(1).filter((l) => l.startsWith('MATCH:'));
      if (matchLines.length !== 2) return ctx.fail('two deny rules');
      if (matchLines[0].includes('rule_id=rule-1') && matchLines[1].includes('rule_id=rule-2')) {
        return ctx.pass();
      }
      return ctx.fail('sorted by rule_id');
    },
  },
  {
    id: 'T014-basic-grant-smoke',
    weightKey: 'basic_smoke',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.gl(['add-principal', '--id', 'u'], s);
      ctx.gl(['grant', '--principal-or-group', 'u', '--resource', '/', '--action', 'read'], s);
      const q = ctx.gl(['query', '--principal', 'u', '--resource', '/any', '--action', 'read'], s);
      if (q.stdout !== 'ALLOW\n') return ctx.fail('basic grant');
      return ctx.pass();
    },
  },
  {
    id: 'T015-composed-precedence-time-nesting',
    weightKey: 'composed_scenarios',
    run(ctx) {
      const s = ctx.freshStore();
      ctx.setupBasicOrg(s);
      ctx.gl(['deny', '--principal-or-group', 'org', '--resource', '/app', '--action', 'read'], s);
      ctx.gl(
        [
          'grant',
          '--principal-or-group',
          'leaf',
          '--resource',
          '/app/v2',
          '--action',
          'read',
          '--valid-from',
          '2025-01-01T00:00:00Z',
          '--valid-until',
          '2025-12-31T00:00:00Z',
        ],
        s
      );
      const ok = ctx.gl(
        [
          'query',
          '--principal',
          'alice',
          '--resource',
          '/app/v2/x',
          '--action',
          'read',
          '--at',
          '2025-06-01T00:00:00Z',
        ],
        s
      );
      const expired = ctx.gl(
        [
          'query',
          '--principal',
          'alice',
          '--resource',
          '/app/v2/x',
          '--action',
          'read',
          '--at',
          '2026-01-01T00:00:00Z',
        ],
        s
      );
      const broadOnly = ctx.gl(
        [
          'query',
          '--principal',
          'alice',
          '--resource',
          '/app/other',
          '--action',
          'read',
          '--at',
          '2025-06-01T00:00:00Z',
        ],
        s
      );
      if (ok.stdout !== 'ALLOW\n') return ctx.fail('composed allow');
      if (expired.stdout !== 'DENY\n') return ctx.fail('composed expired');
      if (broadOnly.stdout !== 'DENY\n') return ctx.fail('broad deny only path');
      return ctx.pass();
    },
  },
];
