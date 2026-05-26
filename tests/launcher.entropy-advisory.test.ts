/**
 * DAR-1148 — demote the entropy backstop to advisory under default-deny.
 *
 * The entropy signal never promotes a var to a handle: handles come only from
 * name-glob matches ∪ declared-managed. An unknown var (not allowlisted, not
 * glob, not declared) is dropped regardless of entropy. When a dropped var's
 * value looks high-entropy, a name-only advisory is surfaced (launch banner +
 * `chaff scan`) — never the value.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { isHandle } from '../src/handles.js';
import { classify } from '../src/policy.js';
import {
  buildHarnessEnv,
  formatLaunchBanner,
  runLauncher,
  DEFAULT_PASSTHROUGH_ALLOWLIST,
} from '../src/launcher.js';
import { buildScanReport, formatScanReport } from '../src/scan.js';
import { buildRedactionSet } from '../src/redaction.js';

let tmp: string;
let logPath: string;
let savedXdg: string | undefined;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-adv-'));
  logPath = join(tmp, 'audit.jsonl');
  savedXdg = process.env.XDG_RUNTIME_DIR;
});

afterEach(() => {
  if (savedXdg === undefined) {
    delete process.env.XDG_RUNTIME_DIR;
  } else {
    process.env.XDG_RUNTIME_DIR = savedXdg;
  }
  rmSync(tmp, { recursive: true, force: true });
});

const SOCK = '/tmp/sock';

// A 32-char high-entropy value (no glob-shaped name will carry it in tests).
const HIGH_ENTROPY = 'aZ9qX2pL7mK4nB8vC1tR3wY6uD0sF5gH';
// A long high-entropy LS_COLORS-style value.
const LS_COLORS_VALUE =
  'di=01;34:ln=01;36:so=01;35:pi=33:ex=01;32:bd=33;01:cd=33;01:su=37;41:sg=30;43';
// A long high-entropy GOROOT-style value (path-like, trips entropy on length+spread).
const GOROOT_VALUE = '/opt/homebrew/Cellar/go/1.22.3/libexec/pkg/tool/darwin_arm64';

describe('ac-1: entropy never promotes a var to a handle', () => {
  it('buildHarnessEnv: a non-allowlisted entropy-only var (SOME_RANDOM_BLOB) is dropped, not a handle, and seeds no BrokerSecret', () => {
    const snapshot = { SOME_RANDOM_BLOB: HIGH_ENTROPY };
    const classification = classify(snapshot, {});
    // sanity: the detector flags it solely on entropy
    expect(classification.SOME_RANDOM_BLOB!.mechanism).toBe('entropy');

    const { env, secrets, handles, dropped } = buildHarnessEnv({
      snapshot,
      classification,
      allowlist: [],
      sockPath: SOCK,
    });
    expect(dropped).toContain('SOME_RANDOM_BLOB');
    expect(handles).not.toContain('SOME_RANDOM_BLOB');
    expect(Object.prototype.hasOwnProperty.call(env, 'SOME_RANDOM_BLOB')).toBe(false);
    expect(secrets.find((s) => s.name === 'SOME_RANDOM_BLOB')).toBeUndefined();
  });

  it('buildHarnessEnv: a name-glob secret (OPENAI_API_KEY vs *_KEY) still becomes a handle with a matching BrokerSecret carrying the real value', () => {
    const snapshot = { OPENAI_API_KEY: 'sk-real-openai-value-123' };
    const classification = classify(snapshot, {});
    expect(classification.OPENAI_API_KEY!.mechanism).toBe('glob');

    const { env, secrets, handles } = buildHarnessEnv({
      snapshot,
      classification,
      allowlist: [],
      sockPath: SOCK,
    });
    expect(handles).toContain('OPENAI_API_KEY');
    expect(isHandle(env.OPENAI_API_KEY!)).toBe(true);
    const secret = secrets.find((s) => s.name === 'OPENAI_API_KEY');
    expect(secret).toBeDefined();
    expect(secret!.value).toBe('sk-real-openai-value-123');
    expect(secret!.handle).toBe(env.OPENAI_API_KEY);
  });

  it('buildHarnessEnv: a declared-managed var the detector does NOT flag (MY_APP_CONFIG, low-entropy, non-glob) still becomes a handle with a matching BrokerSecret', () => {
    const snapshot = { MY_APP_CONFIG: 'production' };
    const classification = classify(snapshot, {});
    expect(classification.MY_APP_CONFIG!.secret).toBe(false);

    const { env, secrets, handles } = buildHarnessEnv({
      snapshot,
      classification,
      allowlist: [],
      declaredManaged: ['MY_APP_CONFIG'],
      sockPath: SOCK,
    });
    expect(handles).toContain('MY_APP_CONFIG');
    expect(isHandle(env.MY_APP_CONFIG!)).toBe(true);
    expect(secrets.find((s) => s.name === 'MY_APP_CONFIG')?.value).toBe('production');
  });

  it('buildHarnessEnv: a high-entropy unknown that is ALSO declared-managed is still a handle (declared-managed overrides the drop; entropy is not what caused the handle)', () => {
    // A non-glob name (so the ONLY detector signal is entropy), declared managed.
    const snapshot = { ODD_NAME_BLOB: HIGH_ENTROPY };
    const classification = classify(snapshot, {});
    expect(classification.ODD_NAME_BLOB!.mechanism).toBe('entropy');

    const { env, secrets, handles, dropped } = buildHarnessEnv({
      snapshot,
      classification,
      allowlist: [],
      declaredManaged: ['ODD_NAME_BLOB'],
      sockPath: SOCK,
    });
    expect(handles).toContain('ODD_NAME_BLOB');
    expect(dropped).not.toContain('ODD_NAME_BLOB');
    expect(isHandle(env.ODD_NAME_BLOB!)).toBe(true);
    expect(secrets.find((s) => s.name === 'ODD_NAME_BLOB')?.value).toBe(HIGH_ENTROPY);
  });

  it('buildHarnessEnv: across a mixed snapshot, the handle bucket equals exactly {glob secret, declared-managed} and the entropy-only unknown is dropped', () => {
    const snapshot = {
      OPENAI_API_KEY: 'sk-real-openai-value-123', // glob
      MY_APP_CONFIG: 'production', // declared-managed
      SOME_RANDOM_BLOB: HIGH_ENTROPY, // entropy-only
      EDITOR: 'vim', // ordinary unknown
    };
    const { handles, dropped } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      declaredManaged: ['MY_APP_CONFIG'],
      sockPath: SOCK,
    });
    expect(handles.slice().sort()).toEqual(['MY_APP_CONFIG', 'OPENAI_API_KEY']);
    expect(dropped).toContain('SOME_RANDOM_BLOB');
    expect(dropped).toContain('EDITOR');
  });

  it('end-to-end via runLauncher: the harness env has a handle for a glob secret but the entropy-only unknown name is absent (dropped, not resolved)', async () => {
    const recordFile = join(tmp, 'record.json');
    const script = join(tmp, 'dummy.mjs');
    writeFileSync(
      script,
      `import { writeFileSync } from 'node:fs';
       writeFileSync(${JSON.stringify(recordFile)}, JSON.stringify({ env: process.env }));
      `,
    );

    const snapshot = {
      OPENAI_API_KEY: 'sk-real-openai-value-123',
      SOME_RANDOM_BLOB: HIGH_ENTROPY,
      XDG_RUNTIME_DIR: tmp,
    };
    const code = await runLauncher({
      argv: [process.execPath, script],
      env: snapshot,
      auditLogPath: logPath,
      stderr: { write: () => true },
    });
    expect(code).toBe(0);

    const record = JSON.parse(execFileSync('cat', [recordFile], { encoding: 'utf8' })) as {
      env: Record<string, string>;
    };
    expect(isHandle(record.env.OPENAI_API_KEY!)).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(record.env, 'SOME_RANDOM_BLOB')).toBe(false);
  });
});

describe('ac-2: dropped high-entropy vars surface a name-only advisory', () => {
  it('buildHarnessEnv: a dropped high-entropy var (FOO) produces an advisory naming FOO without its value', () => {
    const snapshot = { FOO: HIGH_ENTROPY };
    const { dropped, warnings } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      sockPath: SOCK,
    });
    expect(dropped).toContain('FOO');
    const joined = warnings.join('\n');
    expect(joined).toContain('FOO');
    expect(joined).not.toContain(HIGH_ENTROPY);
  });

  it('buildHarnessEnv: a dropped LOW-entropy var (EDITOR=vim) produces NO high-entropy-drop advisory', () => {
    const snapshot = { EDITOR: 'vim' };
    const { dropped, warnings } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      sockPath: SOCK,
    });
    expect(dropped).toContain('EDITOR');
    expect(warnings.join('\n')).not.toContain('EDITOR');
  });

  it('formatLaunchBanner: when a high-entropy var was dropped, the banner names it and not its value', () => {
    const snapshot = { FOO: HIGH_ENTROPY };
    const build = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      sockPath: SOCK,
    });
    const banner = formatLaunchBanner(build);
    expect(banner).toContain('FOO');
    expect(banner).not.toContain(HIGH_ENTROPY);
  });

  it('formatScanReport / buildScanReport: a high-entropy var that would be dropped is named in the report advisories, value excluded', () => {
    const snapshot = { FOO: HIGH_ENTROPY };
    const report = buildScanReport({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
    });
    expect(report.dropped).toContain('FOO');
    const advisoriesJoined = report.advisories.join('\n');
    expect(advisoriesJoined).toContain('FOO');
    expect(advisoriesJoined).not.toContain(HIGH_ENTROPY);

    const text = formatScanReport(report, report.skipped);
    expect(text).toContain('FOO');
    expect(text).not.toContain(HIGH_ENTROPY);
  });

  it('buildHarnessEnv: the high-entropy-drop advisory names every dropped high-entropy var and only those', () => {
    const lowEntropyValue = HIGH_ENTROPY.slice(0, 2); // short, cannot trip entropy
    const snapshot = {
      FOO: HIGH_ENTROPY, // dropped high-entropy → advised
      BAR: HIGH_ENTROPY, // dropped high-entropy → advised
      EDITOR: 'vim', // dropped low-entropy → not advised
      SHORT_THING: lowEntropyValue, // dropped low-entropy → not advised
      PATH: '/usr/bin', // passthrough → not advised
    };
    const { warnings } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: ['PATH'],
      sockPath: SOCK,
    });
    const joined = warnings.join('\n');
    expect(joined).toContain('FOO');
    expect(joined).toContain('BAR');
    expect(joined).not.toContain('EDITOR');
    expect(joined).not.toContain('SHORT_THING');
    expect(joined).not.toContain('PATH');
  });

  it('end-to-end via runLauncher: the banner on stderr names a dropped high-entropy var and contains none of its value', async () => {
    const script = join(tmp, 'noop.mjs');
    writeFileSync(script, 'process.exit(0);\n');
    let stderrText = '';
    const snapshot = {
      FOO: HIGH_ENTROPY,
      PATH: '/usr/bin',
      XDG_RUNTIME_DIR: tmp,
    };
    await runLauncher({
      argv: [process.execPath, script],
      env: snapshot,
      auditLogPath: logPath,
      stderr: {
        write: (chunk: string) => {
          stderrText += chunk;
          return true;
        },
      },
    });
    expect(stderrText).toContain('FOO');
    expect(stderrText).not.toContain(HIGH_ENTROPY);
  });
});

describe('ac-3: the allowlist-beats-entropy carve-out is simplified away', () => {
  // A realistic macOS TMPDIR: long, high per-char entropy → trips the entropy
  // backstop, but it is on the documented passthrough allowlist.
  const realisticTmpdir = '/var/folders/3x/9zq8h2_n1bs0gk5x7lp4tq9w0000gn/T/';

  it('buildHarnessEnv: an entropy-flagged ALLOWLISTED var (TMPDIR) is passed through verbatim (isHandle false)', () => {
    const snapshot = { TMPDIR: realisticTmpdir };
    const c = classify(snapshot, {});
    expect(c.TMPDIR!.mechanism).toBe('entropy'); // sanity: entropy trips
    const { env, passthrough, handles } = buildHarnessEnv({
      snapshot,
      classification: c,
      allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST,
      sockPath: SOCK,
    });
    expect(env.TMPDIR).toBe(realisticTmpdir);
    expect(passthrough).toContain('TMPDIR');
    expect(handles).not.toContain('TMPDIR');
    expect(isHandle(env.TMPDIR!)).toBe(false);
  });

  it('buildHarnessEnv: an entropy-flagged allowlisted var (TMPDIR) raises no advisory warning', () => {
    const snapshot = { TMPDIR: realisticTmpdir };
    const { warnings } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST,
      sockPath: SOCK,
    });
    expect(warnings.join('\n')).not.toContain('TMPDIR');
  });

  it('buildHarnessEnv: an entropy-flagged NON-allowlisted var is dropped (not a handle) — entropy treated uniformly regardless of allowlist', () => {
    const snapshot = { SOME_RANDOM_BLOB: HIGH_ENTROPY };
    const { env, handles, dropped } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      sockPath: SOCK,
    });
    expect(dropped).toContain('SOME_RANDOM_BLOB');
    expect(handles).not.toContain('SOME_RANDOM_BLOB');
    expect(Object.prototype.hasOwnProperty.call(env, 'SOME_RANDOM_BLOB')).toBe(false);
  });
});

describe('ac-4: benign high-entropy vars are dropped and never enter broker/redaction set', () => {
  it('buildHarnessEnv: LS_COLORS (long high-entropy) is dropped and absent from the built env', () => {
    const snapshot = { LS_COLORS: LS_COLORS_VALUE };
    const { env, dropped } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST,
      sockPath: SOCK,
    });
    expect(dropped).toContain('LS_COLORS');
    expect(Object.prototype.hasOwnProperty.call(env, 'LS_COLORS')).toBe(false);
    expect(JSON.stringify(env)).not.toContain(LS_COLORS_VALUE);
  });

  it('buildHarnessEnv: a long high-entropy GOROOT-style var is dropped and produces no BrokerSecret', () => {
    const snapshot = { GOROOT: GOROOT_VALUE };
    const { secrets, dropped } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST,
      sockPath: SOCK,
    });
    expect(dropped).toContain('GOROOT');
    expect(secrets.find((s) => s.name === 'GOROOT')).toBeUndefined();
  });

  it('buildHarnessEnv: an npm_package_* var with a high-entropy value is dropped and not in secrets', () => {
    const snapshot = { npm_package_dependencies_left_pad: HIGH_ENTROPY };
    const { secrets, dropped } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST,
      sockPath: SOCK,
    });
    expect(dropped).toContain('npm_package_dependencies_left_pad');
    expect(secrets.find((s) => s.name === 'npm_package_dependencies_left_pad')).toBeUndefined();
  });

  it('redaction integration: a snapshot of only benign high-entropy vars yields zero secrets, so buildRedactionSet produces an empty pattern set', () => {
    const snapshot = {
      LS_COLORS: LS_COLORS_VALUE,
      GOROOT: GOROOT_VALUE,
      npm_package_version: HIGH_ENTROPY,
    };
    const { secrets } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST,
      sockPath: SOCK,
    });
    expect(secrets).toHaveLength(0);
    const gated = buildRedactionSet({ secrets });
    expect(gated.patterns).toHaveLength(0);
  });
});

describe('ac-5: combined scenario + advisory hygiene', () => {
  it('one snapshot: high-entropy unknown dropped with by-name advisory (no value); glob secret and declared-managed both handles with matching BrokerSecrets', () => {
    const snapshot = {
      SOME_RANDOM_BLOB: HIGH_ENTROPY, // entropy-only unknown
      OPENAI_API_KEY: 'sk-real-openai-value-123', // glob
      MY_APP_CONFIG: 'production', // declared-managed
    };
    const { handles, dropped, secrets, warnings } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      declaredManaged: ['MY_APP_CONFIG'],
      sockPath: SOCK,
    });

    expect(dropped).toContain('SOME_RANDOM_BLOB');
    const joined = warnings.join('\n');
    expect(joined).toContain('SOME_RANDOM_BLOB');
    expect(joined).not.toContain(HIGH_ENTROPY);

    expect(handles.slice().sort()).toEqual(['MY_APP_CONFIG', 'OPENAI_API_KEY']);
    expect(secrets.find((s) => s.name === 'OPENAI_API_KEY')?.value).toBe(
      'sk-real-openai-value-123',
    );
    expect(secrets.find((s) => s.name === 'MY_APP_CONFIG')?.value).toBe('production');
  });

  it('advisory hygiene: across a snapshot mixing dropped high-entropy vars and an allowlisted secret-looking var, no advisory contains any value', () => {
    const snapshot = {
      FOO: HIGH_ENTROPY, // dropped high-entropy
      BAR: HIGH_ENTROPY, // dropped high-entropy
      TMPDIR: '/var/folders/3x/9zq8h2_n1bs0gk5x7lp4tq9w0000gn/T/', // allowlisted, entropy-tripping
    };
    const { warnings } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST,
      sockPath: SOCK,
    });
    const joined = warnings.join('\n');
    for (const value of Object.values(snapshot)) {
      expect(joined).not.toContain(value);
    }
  });
});
