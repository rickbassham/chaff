/**
 * DAR-1139 — default-deny harness env: allowlist passthrough + drop unknowns.
 *
 * Exercises the three-bucket model of {@link buildHarnessEnv}: a var is
 * passthrough (name on the effective allowlist → value verbatim), a handle
 * (managed secret = detected-secret ∪ declared-managed → handle + broker
 * secret), or dropped (neither → absent from the harness env entirely). The
 * precedence rule treats an allowlisted-but-detected-secret var as a handle
 * with an advisory warning, and {@link formatLaunchBanner} reports per bucket
 * (passthrough count, handle names, dropped count) names-only, never values.
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

let tmp: string;
let logPath: string;
let savedXdg: string | undefined;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-dd-'));
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

describe('ac-1: buildHarnessEnv sorts each var into exactly one bucket', () => {
  it('an allowlisted non-secret var (PATH) appears in the built env with its value verbatim', () => {
    const snapshot = { PATH: '/usr/bin:/bin' };
    const { env } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: ['PATH'],
      sockPath: SOCK,
    });
    expect(env.PATH).toBe(snapshot.PATH);
  });

  it('a managed-secret var (OPENAI_API_KEY, detected by glob) is a value isHandle() accepts, and a matching BrokerSecret carries the real value', () => {
    const snapshot = { OPENAI_API_KEY: 'sk-real-openai-value-123' };
    const { env, secrets } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      sockPath: SOCK,
    });
    expect(isHandle(env.OPENAI_API_KEY!)).toBe(true);
    const secret = secrets.find((s) => s.name === 'OPENAI_API_KEY');
    expect(secret).toBeDefined();
    expect(secret!.value).toBe(snapshot.OPENAI_API_KEY);
    expect(secret!.handle).toBe(env.OPENAI_API_KEY);
  });

  it('a var that is neither allowlisted nor managed-secret (EDITOR=vim) is absent from the built env: name not a key, value not in the serialized env', () => {
    const snapshot = { EDITOR: 'vim' };
    const { env } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      sockPath: SOCK,
    });
    expect(Object.prototype.hasOwnProperty.call(env, 'EDITOR')).toBe(false);
    expect(JSON.stringify(env)).not.toContain('vim');
  });

  it('every snapshot var lands in exactly one bucket: built-env keys (minus CHAFF_SOCK) === passthrough ∪ handle, passthrough ∩ handle empty, dropped = snapshot names not in that union', () => {
    const snapshot = {
      PATH: '/usr/bin',
      OPENAI_API_KEY: 'sk-real-openai-value-123',
      EDITOR: 'vim',
    };
    const build = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: ['PATH'],
      sockPath: SOCK,
    });

    const passthrough = new Set(build.passthrough);
    const handles = new Set(build.handles);
    const dropped = new Set(build.dropped);

    // passthrough ∩ handle is empty
    for (const name of passthrough) {
      expect(handles.has(name)).toBe(false);
    }

    // built-env keys minus CHAFF_SOCK === passthrough ∪ handle
    const envKeys = Object.keys(build.env)
      .filter((k) => k !== 'CHAFF_SOCK')
      .sort();
    const union = [...new Set([...passthrough, ...handles])].sort();
    expect(envKeys).toEqual(union);

    // dropped === snapshot names not in the union
    const expectedDropped = Object.keys(snapshot)
      .filter((n) => !passthrough.has(n) && !handles.has(n))
      .sort();
    expect([...dropped].sort()).toEqual(expectedDropped);

    // and every snapshot name is in exactly one bucket
    for (const name of Object.keys(snapshot)) {
      const inCount =
        (passthrough.has(name) ? 1 : 0) + (handles.has(name) ? 1 : 0) + (dropped.has(name) ? 1 : 0);
      expect(inCount).toBe(1);
    }
  });

  it('CHAFF_SOCK is always present, set to sockPath, even when every var is dropped and even when the snapshot is empty', () => {
    const dropAll = { EDITOR: 'vim', SECRET_LESS_THING: 'value' };
    const a = buildHarnessEnv({
      snapshot: dropAll,
      classification: classify(dropAll, {}),
      allowlist: [],
      sockPath: SOCK,
    });
    expect(a.env.CHAFF_SOCK).toBe(SOCK);
    // none of the (dropped) vars survived
    expect(Object.keys(a.env)).toEqual(['CHAFF_SOCK']);

    const empty = buildHarnessEnv({
      snapshot: {},
      classification: {},
      allowlist: [],
      sockPath: SOCK,
    });
    expect(empty.env.CHAFF_SOCK).toBe(SOCK);
    expect(Object.keys(empty.env)).toEqual(['CHAFF_SOCK']);
  });

  it('end-to-end via runLauncher: the harness sees an allowlisted var verbatim, a managed-secret var as a handle, a non-allowlisted non-secret var absent, and CHAFF_SOCK set', async () => {
    const recordFile = join(tmp, 'record.json');
    const script = join(tmp, 'dummy.mjs');
    writeFileSync(
      script,
      `import { writeFileSync } from 'node:fs';
       writeFileSync(${JSON.stringify(recordFile)}, JSON.stringify({ env: process.env }));
      `,
    );

    const snapshot = {
      PATH: '/usr/bin:/bin',
      OPENAI_API_KEY: 'sk-real-openai-value-123',
      EDITOR: 'vim',
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
    // PATH is on the default passthrough allowlist → verbatim.
    expect(record.env.PATH).toBe('/usr/bin:/bin');
    // OPENAI_API_KEY is detected-secret → handle.
    expect(isHandle(record.env.OPENAI_API_KEY!)).toBe(true);
    // EDITOR is neither → absent.
    expect(Object.prototype.hasOwnProperty.call(record.env, 'EDITOR')).toBe(false);
    // CHAFF_SOCK is set.
    expect(typeof record.env.CHAFF_SOCK).toBe('string');
    expect(record.env.CHAFF_SOCK!.length).toBeGreaterThan(0);
  });
});

describe('ac-2: declaredManaged parameter (defaults empty)', () => {
  it('a var named in declaredManaged that the detector does NOT flag (MY_APP_CONFIG, low-entropy, non-glob) becomes a handle with a matching BrokerSecret', () => {
    const snapshot = { MY_APP_CONFIG: 'production' };
    const classification = classify(snapshot, {});
    // sanity: the detector does not flag it
    expect(classification.MY_APP_CONFIG!.secret).toBe(false);

    const { env, secrets } = buildHarnessEnv({
      snapshot,
      classification,
      allowlist: [],
      declaredManaged: ['MY_APP_CONFIG'],
      sockPath: SOCK,
    });
    expect(isHandle(env.MY_APP_CONFIG!)).toBe(true);
    const secret = secrets.find((s) => s.name === 'MY_APP_CONFIG');
    expect(secret).toBeDefined();
    expect(secret!.value).toBe('production');
    expect(secret!.handle).toBe(env.MY_APP_CONFIG);
  });

  it('when declaredManaged is omitted/empty, a var that is neither detected-secret nor allowlisted is dropped (no implicit managed set)', () => {
    const snapshot = { MY_APP_CONFIG: 'production' };
    const { env, dropped } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      sockPath: SOCK,
    });
    expect(Object.prototype.hasOwnProperty.call(env, 'MY_APP_CONFIG')).toBe(false);
    expect(dropped).toContain('MY_APP_CONFIG');
  });
});

describe('ac-3: precedence — allowlisted AND detected-secret → handle + advisory warning', () => {
  // A var on the effective allowlist whose NAME also matches a secret glob.
  const snapshot = { API_TOKEN: 'real-token-value-789' };
  const classification = classify(snapshot, {});

  it('an allowlisted-but-secret-looking var (API_TOKEN matches *_TOKEN) becomes a handle and is NOT passed through verbatim', () => {
    expect(classification.API_TOKEN!.secret).toBe(true); // sanity: detected
    const { env } = buildHarnessEnv({
      snapshot,
      classification,
      allowlist: ['API_TOKEN'],
      sockPath: SOCK,
    });
    expect(isHandle(env.API_TOKEN!)).toBe(true);
    expect(env.API_TOKEN).not.toBe('real-token-value-789');
  });

  it('for that var, the real value is not in the serialized env and a matching BrokerSecret carries it', () => {
    const { env, secrets } = buildHarnessEnv({
      snapshot,
      classification,
      allowlist: ['API_TOKEN'],
      sockPath: SOCK,
    });
    expect(JSON.stringify(env)).not.toContain('real-token-value-789');
    const secret = secrets.find((s) => s.name === 'API_TOKEN');
    expect(secret).toBeDefined();
    expect(secret!.value).toBe('real-token-value-789');
  });

  it('the build surfaces an advisory warning naming that var (by name only, never its value)', () => {
    const { warnings } = buildHarnessEnv({
      snapshot,
      classification,
      allowlist: ['API_TOKEN'],
      sockPath: SOCK,
    });
    const joined = warnings.join('\n');
    expect(joined).toContain('API_TOKEN');
    expect(joined).not.toContain('real-token-value-789');
  });
});

describe('ac-4: documented default passthrough allowlist', () => {
  const LITERALS = [
    'PATH',
    'HOME',
    'SHELL',
    'TERM',
    'LANG',
    'TZ',
    'TMPDIR',
    'USER',
    'LOGNAME',
    'PWD',
  ];

  it('the exported default passthrough allowlist contains each documented literal name', () => {
    for (const name of LITERALS) {
      expect(DEFAULT_PASSTHROUGH_ALLOWLIST).toContain(name);
    }
  });

  it('the default allowlist matches the LC_* family (LC_ALL, LC_CTYPE) → bucketed passthrough', () => {
    const snapshot = { LC_ALL: 'en_US.UTF-8', LC_CTYPE: 'en_US.UTF-8' };
    const { passthrough, env } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST,
      sockPath: SOCK,
    });
    expect(passthrough).toContain('LC_ALL');
    expect(passthrough).toContain('LC_CTYPE');
    expect(env.LC_ALL).toBe('en_US.UTF-8');
    expect(env.LC_CTYPE).toBe('en_US.UTF-8');
  });

  it('the default allowlist matches the XDG_* family (XDG_RUNTIME_DIR, XDG_CONFIG_HOME) → bucketed passthrough', () => {
    const snapshot = { XDG_RUNTIME_DIR: '/run/user/1000', XDG_CONFIG_HOME: '/home/u/.config' };
    const { passthrough, env } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST,
      sockPath: SOCK,
    });
    expect(passthrough).toContain('XDG_RUNTIME_DIR');
    expect(passthrough).toContain('XDG_CONFIG_HOME');
    expect(env.XDG_RUNTIME_DIR).toBe('/run/user/1000');
    expect(env.XDG_CONFIG_HOME).toBe('/home/u/.config');
  });

  it('with the default allowlist in effect, a representative snapshot of those vars is bucketed passthrough (value verbatim) rather than dropped', () => {
    const snapshot: Record<string, string> = {
      PATH: '/usr/bin',
      HOME: '/home/u',
      SHELL: '/bin/zsh',
      TERM: 'xterm-256color',
      LANG: 'en_US.UTF-8',
      LC_ALL: 'en_US.UTF-8',
      TZ: 'UTC',
      TMPDIR: '/tmp',
      USER: 'u',
      LOGNAME: 'u',
      PWD: '/home/u/proj',
      XDG_RUNTIME_DIR: '/run/user/1000',
    };
    const { passthrough, dropped, env } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST,
      sockPath: SOCK,
    });
    for (const [name, value] of Object.entries(snapshot)) {
      expect(passthrough).toContain(name);
      expect(dropped).not.toContain(name);
      expect(env[name]).toBe(value);
    }
  });
});

describe('ac-5: launch banner reports per bucket — names only, never values', () => {
  // 3 passthrough, 2 handles (1 detected, 1 declared), 2 dropped, 1 advisory.
  function build() {
    const snapshot = {
      PATH: '/usr/bin',
      HOME: '/home/u',
      LANG: 'en_US.UTF-8',
      OPENAI_API_KEY: 'sk-real-openai-value-123',
      MY_APP_CONFIG: 'production',
      EDITOR: 'vim',
      PAGER: 'less',
      API_TOKEN: 'real-token-value-789',
    };
    return buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: ['PATH', 'HOME', 'LANG', 'API_TOKEN'],
      declaredManaged: ['MY_APP_CONFIG'],
      sockPath: SOCK,
    });
  }

  it('the banner contains the passthrough COUNT equal to the number of passthrough vars', () => {
    const b = build();
    const banner = formatLaunchBanner(b);
    expect(banner).toContain(String(b.passthrough.length));
    // explicit: 3 passthrough (PATH, HOME, LANG; API_TOKEN is a handle by precedence)
    expect(b.passthrough.length).toBe(3);
  });

  it('the banner does NOT contain any individual passthrough var name (passthrough is count-only)', () => {
    const b = build();
    const banner = formatLaunchBanner(b);
    for (const name of b.passthrough) {
      expect(banner).not.toContain(name);
    }
  });

  it('the banner lists each handle var by NAME and the names match exactly the handle bucket', () => {
    const b = build();
    const banner = formatLaunchBanner(b);
    for (const name of b.handles) {
      expect(banner).toContain(name);
    }
    expect(b.handles.slice().sort()).toEqual(['API_TOKEN', 'MY_APP_CONFIG', 'OPENAI_API_KEY']);
  });

  it('the banner reports the dropped bucket as a COUNT matching the number of dropped vars', () => {
    const b = build();
    const banner = formatLaunchBanner(b);
    expect(b.dropped.length).toBe(2);
    expect(banner).toContain(String(b.dropped.length));
  });

  it('the banner contains no env VALUE for any bucket', () => {
    const b = build();
    const banner = formatLaunchBanner(b);
    const snapshotValues = [
      '/usr/bin',
      '/home/u',
      'en_US.UTF-8',
      'sk-real-openai-value-123',
      'production',
      'vim',
      'less',
      'real-token-value-789',
    ];
    for (const value of snapshotValues) {
      expect(banner).not.toContain(value);
    }
  });

  it('the advisory warning for the allowlisted-but-secret-looking var appears in the banner by name, with no value', () => {
    const b = build();
    const banner = formatLaunchBanner(b);
    expect(banner).toContain('API_TOKEN');
    expect(banner).not.toContain('real-token-value-789');
  });

  it('end-to-end via runLauncher: the banner is written to stderr and contains a handle var name but no secret value', async () => {
    const script = join(tmp, 'noop.mjs');
    writeFileSync(script, 'process.exit(0);\n');
    let stderrText = '';
    const snapshot = {
      OPENAI_API_KEY: 'sk-real-openai-value-123',
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
    expect(stderrText).toContain('OPENAI_API_KEY');
    expect(stderrText).not.toContain('sk-real-openai-value-123');
  });
});

describe('ac-6: README → PLAN.md intra-repo link resolves', () => {
  it('the README links to ./PLAN.md and that file exists on disk', () => {
    const repoRoot = join(import.meta.dirname, '..');
    const readme = execFileSync('cat', [join(repoRoot, 'README.md')], { encoding: 'utf8' });
    expect(readme).toContain('./PLAN.md');
    // the linked path is present on disk
    const planExists = (() => {
      try {
        execFileSync('test', ['-f', join(repoRoot, 'PLAN.md')]);
        return true;
      } catch {
        return false;
      }
    })();
    expect(planExists).toBe(true);
  });
});

describe('ac-7: issue explicit required cases (restatements)', () => {
  it('non-allowlisted non-secret var is absent from the built env', () => {
    const snapshot = { EDITOR: 'vim' };
    const { env } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      sockPath: SOCK,
    });
    expect(Object.prototype.hasOwnProperty.call(env, 'EDITOR')).toBe(false);
  });

  it('allowlisted var passes through verbatim', () => {
    const snapshot = { PATH: '/usr/bin' };
    const { env } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: ['PATH'],
      sockPath: SOCK,
    });
    expect(env.PATH).toBe('/usr/bin');
  });

  it('detected secret becomes a handle and seeds a matching BrokerSecret', () => {
    const snapshot = { DB_TOKEN: 'real-db-token-value-456' };
    const { env, secrets } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      sockPath: SOCK,
    });
    expect(isHandle(env.DB_TOKEN!)).toBe(true);
    expect(secrets.find((s) => s.name === 'DB_TOKEN')?.value).toBe('real-db-token-value-456');
  });

  it('allowlisted-but-secret-looking var becomes a handle plus an advisory warning', () => {
    const snapshot = { API_TOKEN: 'real-token-value-789' };
    const { env, warnings } = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: ['API_TOKEN'],
      sockPath: SOCK,
    });
    expect(isHandle(env.API_TOKEN!)).toBe(true);
    expect(warnings.join('\n')).toContain('API_TOKEN');
  });

  it('CHAFF_SOCK is present in the built env', () => {
    const { env } = buildHarnessEnv({
      snapshot: {},
      classification: {},
      allowlist: [],
      sockPath: SOCK,
    });
    expect(env.CHAFF_SOCK).toBe(SOCK);
  });

  it('the default allowlist contains the documented names', () => {
    for (const name of [
      'PATH',
      'HOME',
      'SHELL',
      'TERM',
      'LANG',
      'TZ',
      'TMPDIR',
      'USER',
      'LOGNAME',
      'PWD',
    ]) {
      expect(DEFAULT_PASSTHROUGH_ALLOWLIST).toContain(name);
    }
  });
});
