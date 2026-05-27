/**
 * DAR-1141 — `chaff scan` three-bucket default-deny report.
 *
 * Supersedes the DAR-1098 secret/non-secret two-bucket report. Scan now reports
 * passthrough / handle / dropped under the *effective* allowlist +
 * declared-managed config (defaults → user → folder), reusing buildHarnessEnv's
 * bucketing (single source of truth), surfaces advisories, and never prints a
 * value.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { classify } from '../src/policy.js';
import { buildHarnessEnv, DEFAULT_PASSTHROUGH_ALLOWLIST } from '../src/launcher.js';
import { type LevelConfig } from '../src/config.js';
import { buildScanReport, formatScanReport, runScan, type ScanReport } from '../src/scan.js';
import { startBroker, type Broker } from '../src/broker.js';
import { writeConfig } from './helpers/config-seed.js';

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const BIN = join(SRC_DIR, '..', 'dist', 'bin', 'chaff.js');

/** Build a scan report from a snapshot under the given effective config. */
function reportFor(args: {
  snapshot: Record<string, string>;
  allowlist?: readonly string[];
  declaredManaged?: readonly string[];
  configWarnings?: readonly string[];
  forceScrub?: readonly string[];
}): ScanReport {
  return buildScanReport({
    snapshot: args.snapshot,
    classification: classify(args.snapshot, {}),
    allowlist: args.allowlist ?? DEFAULT_PASSTHROUGH_ALLOWLIST,
    declaredManaged: args.declaredManaged,
    configWarnings: args.configWarnings,
    forceScrub: args.forceScrub,
  });
}

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-scan-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

/** Run `chaff scan` via the built binary; return {stdout, stderr, status}. */
function runChaffScan(
  extraEnv: Record<string, string>,
  cwd?: string,
): {
  stdout: string;
  stderr: string;
  status: number;
} {
  try {
    const stdout = execFileSync(process.execPath, [BIN, 'scan'], {
      encoding: 'utf8',
      env: { ...process.env, ...extraEnv },
      cwd: cwd ?? process.cwd(),
    });
    return { stdout, stderr: '', status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
  }
}

function requireBin(): void {
  if (!existsSync(BIN)) {
    throw new Error(`built binary missing at ${BIN}; run \`make build\` first`);
  }
}

describe('ac-1: scan reports passthrough / handle / dropped under the effective config', () => {
  it('buildScanReport, given a seeded snapshot + effective config (allowlist + declaredManaged), partitions every var into exactly one of passthrough/handle/dropped: every input var name appears in exactly one bucket, none missing, none duplicated across buckets', () => {
    const snapshot = {
      OPENAI_API_KEY: 'sk-secret-sentinel',
      PATH: '/usr/bin:/bin',
      EXTRA_OK: 'fine',
      APP_MODE: 'production',
      EDITOR: 'vim',
    };
    const report = reportFor({
      snapshot,
      allowlist: [...DEFAULT_PASSTHROUGH_ALLOWLIST, 'EXTRA_OK'],
      declaredManaged: ['APP_MODE'],
    });

    const all = [...report.passthrough, ...report.handles, ...report.dropped].sort();
    expect(all).toEqual(Object.keys(snapshot).sort());
    expect(new Set(all).size).toBe(all.length);
  });

  it('buildScanReport classifies a seeded snapshot into the same buckets buildHarnessEnv produces for the same {snapshot, classification, allowlist, declaredManaged}: passthrough names equal build.passthrough, handle names equal build.handles, dropped names equal build.dropped', () => {
    const snapshot = {
      OPENAI_API_KEY: 'sk-secret-sentinel',
      PATH: '/usr/bin:/bin',
      EXTRA_OK: 'fine',
      APP_MODE: 'production',
      EDITOR: 'vim',
    };
    const classification = classify(snapshot, {});
    const allowlist = [...DEFAULT_PASSTHROUGH_ALLOWLIST, 'EXTRA_OK'];
    const declaredManaged = ['APP_MODE'];

    const report = buildScanReport({ snapshot, classification, allowlist, declaredManaged });
    const build = buildHarnessEnv({
      snapshot,
      classification,
      allowlist,
      declaredManaged,
      sockPath: '/tmp/sock',
    });

    expect(report.passthrough).toEqual(build.passthrough);
    expect(report.handles).toEqual(build.handles);
    expect(report.dropped).toEqual(build.dropped);
  });

  it('buildScanReport reflects the effective config: a var on the user/folder-extended allowlist (not a shipped default) lands in passthrough; a declared-managed var the heuristics do NOT flag lands in handles; a var that is neither allowlisted nor managed lands in dropped', () => {
    const snapshot = {
      EXTRA_OK: 'a-fine-value',
      APP_MODE: 'production',
      EDITOR: 'vim',
    };
    const report = reportFor({
      snapshot,
      allowlist: [...DEFAULT_PASSTHROUGH_ALLOWLIST, 'EXTRA_OK'],
      declaredManaged: ['APP_MODE'],
    });

    expect(report.passthrough).toContain('EXTRA_OK');
    expect(report.handles).toContain('APP_MODE');
    expect(report.dropped).toContain('EDITOR');
  });

  it('formatScanReport renders a passthrough section, a handle section, and a dropped section, each labeled; each input var name appears exactly once across the three sections', () => {
    const snapshot = {
      OPENAI_API_KEY: 'sk-secret-sentinel',
      PATH: '/usr/bin:/bin',
      EDITOR: 'vim',
    };
    const report = reportFor({ snapshot });
    const text = formatScanReport(report);

    expect(text).toContain('Passes through unchanged:');
    expect(text).toContain('Would be replaced by handles:');
    expect(text).toContain('Dropped from the harness env:');

    for (const name of Object.keys(snapshot)) {
      const occurrences = text.split(name).length - 1;
      expect(occurrences).toBe(1);
    }
  });

  it("`chaff scan` via the built binary reads its own process env, prints the three-bucket report to stdout, and exits 0 (no 'not implemented yet' path); a seeded allowlisted var appears under passthrough and a seeded glob-secret var appears under handles", () => {
    requireBin();
    const { stdout, status } = runChaffScan({
      // TERM is a shipped-default allowlist entry → passthrough.
      TERM: 'xterm-256color',
      E2E_SCAN_KEY: 'sk-e2e-scan-secret-abc',
    });
    expect(status).toBe(0);
    expect(stdout).not.toContain('not implemented yet');

    const lines = stdout.split('\n');
    const ptIdx = lines.findIndex((l) => l.includes('Passes through unchanged:'));
    const hIdx = lines.findIndex((l) => l.includes('Would be replaced by handles:'));
    const dIdx = lines.findIndex((l) => l.includes('Dropped from the harness env:'));
    // A glob-secret var is a handle; an allowlisted var passes through.
    const handlesSection = lines.slice(hIdx, dIdx).join('\n');
    const passthroughSection = lines.slice(ptIdx, hIdx).join('\n');
    expect(handlesSection).toContain('E2E_SCAN_KEY');
    expect(passthroughSection).toContain('TERM');
  });

  it('`chaff scan` discovers user + folder config on disk (XDG_CONFIG_HOME / cwd .chaff) and reports under the merged effective config: a folder-allowlisted var is reported as passthrough and a user-declared-managed var is reported as a handle in the built-binary output', () => {
    requireBin();
    const cwd = join(tmp, 'repo');
    const userXdg = join(tmp, 'xdg');
    mkdirSync(join(cwd, '.chaff'), { recursive: true });
    mkdirSync(join(userXdg, 'chaff'), { recursive: true });
    const folder: LevelConfig = { allowlist: ['REPO_SETTING'], declaredManaged: [] };
    const user: LevelConfig = { allowlist: [], declaredManaged: ['MY_APP_CONFIG'] };
    writeConfig(join(cwd, '.chaff'), folder);
    writeConfig(join(userXdg, 'chaff'), user);

    const { stdout, status } = runChaffScan(
      {
        XDG_CONFIG_HOME: userXdg,
        REPO_SETTING: 'repo-value',
        MY_APP_CONFIG: 'production',
      },
      cwd,
    );
    expect(status).toBe(0);

    const lines = stdout.split('\n');
    const ptIdx = lines.findIndex((l) => l.includes('Passes through unchanged:'));
    const hIdx = lines.findIndex((l) => l.includes('Would be replaced by handles:'));
    const dIdx = lines.findIndex((l) => l.includes('Dropped from the harness env:'));
    const passthroughSection = lines.slice(ptIdx, hIdx).join('\n');
    const handlesSection = lines.slice(hIdx, dIdx).join('\n');
    expect(passthroughSection).toContain('REPO_SETTING');
    expect(handlesSection).toContain('MY_APP_CONFIG');
  });
});

describe('ac-2: scan reuses buildHarnessEnv bucketing (single source of truth)', () => {
  it("scan derives its buckets by calling buildHarnessEnv (or its extracted bucketing core) rather than re-implementing secret-vs-passthrough partitioning: for a snapshot exercising glob-secret, entropy-secret, allowlisted, declared-managed, allowlisted-but-secret-looking, and dropped cases, scan's reported buckets equal buildHarnessEnv's passthrough/handles/dropped exactly", () => {
    const snapshot = {
      OPENAI_API_KEY: 'sk-glob-secret',
      RANDOM_BLOB: 'a8Fk2Lp9Qz3Wm7Xb4Vn6Yc1Td5Rg0Hj',
      PATH: '/usr/bin:/bin',
      APP_MODE: 'production',
      // allowlisted but a name-glob secret → handle (precedence rule).
      SESSION_TOKEN: 'tok-value',
      EDITOR: 'vim',
    };
    const classification = classify(snapshot, {});
    const allowlist = [...DEFAULT_PASSTHROUGH_ALLOWLIST, 'SESSION_TOKEN'];
    const declaredManaged = ['APP_MODE'];

    const report = buildScanReport({ snapshot, classification, allowlist, declaredManaged });
    const build = buildHarnessEnv({
      snapshot,
      classification,
      allowlist,
      declaredManaged,
      sockPath: '/tmp/sock',
    });

    expect(report.passthrough).toEqual(build.passthrough);
    expect(report.handles).toEqual(build.handles);
    expect(report.dropped).toEqual(build.dropped);
  });

  it("entropy is advisory-only in scan because it shares buildHarnessEnv (DAR-1148): an allowlisted var whose value trips ONLY the entropy backstop is reported as passthrough (not handle), matching buildHarnessEnv's behavior", () => {
    // A long high-entropy value on an allowlisted name: the entropy backstop
    // fires but never sources a handle, and the allowlist name passes it through.
    const snapshot = { ENTROPY_OK: 'a8Fk2Lp9Qz3Wm7Xb4Vn6Yc1Td5Rg0Hj' };
    const classification = classify(snapshot, {});
    expect(classification.ENTROPY_OK!.mechanism).toBe('entropy');

    const report = reportFor({
      snapshot,
      allowlist: [...DEFAULT_PASSTHROUGH_ALLOWLIST, 'ENTROPY_OK'],
    });
    expect(report.passthrough).toContain('ENTROPY_OK');
    expect(report.handles).not.toContain('ENTROPY_OK');
  });

  it('the handle-over-passthrough precedence is honored by scan: a var that is both allowlisted AND a name-glob/declared-managed secret is reported as a handle (not passthrough), matching buildHarnessEnv', () => {
    const snapshot = { SESSION_TOKEN: 'tok-value' };
    const report = reportFor({
      snapshot,
      allowlist: [...DEFAULT_PASSTHROUGH_ALLOWLIST, 'SESSION_TOKEN'],
    });
    expect(report.handles).toContain('SESSION_TOKEN');
    expect(report.passthrough).not.toContain('SESSION_TOKEN');
  });

  it('scan no longer buckets vars via a plain classify-only secret/non-secret split (the old DAR-1098 divergent classifier path is removed): a declared-managed var with a benign non-secret value is reported as a handle (impossible under a plain classify-only classifier)', () => {
    const snapshot = { DEPLOY_REGION: 'us-east-1' };
    const classification = classify(snapshot, {});
    // The advisory classifier does NOT flag a benign value as secret...
    expect(classification.DEPLOY_REGION!.secret).toBe(false);

    // ...yet scan reports it as a handle because it is declared-managed, which
    // only the buildHarnessEnv code path produces.
    const report = reportFor({ snapshot, declaredManaged: ['DEPLOY_REGION'] });
    expect(report.handles).toContain('DEPLOY_REGION');
    expect(report.passthrough).not.toContain('DEPLOY_REGION');
    expect(report.dropped).not.toContain('DEPLOY_REGION');
  });
});

describe('ac-3: scan surfaces advisories', () => {
  it('scan surfaces an allowlisted-but-secret-looking advisory by NAME: given a snapshot where an allowlisted var value trips the name-glob/declared-managed secret signal, the report includes an advisory naming that var (the same warning buildHarnessEnv emits), and no value appears in the advisory text', () => {
    const snapshot = { SESSION_TOKEN: 'tok-sentinel-value' };
    const report = reportFor({
      snapshot,
      allowlist: [...DEFAULT_PASSTHROUGH_ALLOWLIST, 'SESSION_TOKEN'],
    });

    expect(report.advisories.some((a) => a.includes('SESSION_TOKEN'))).toBe(true);
    for (const advisory of report.advisories) {
      expect(advisory).not.toContain('tok-sentinel-value');
    }
  });

  it('scan surfaces folder-trust advisories from the effective config: given a folder-allowlisted var whose value trips the heuristics, the report includes the folder-trust warning naming that var (carried through from loadEffectiveConfig.warnings), value never printed', () => {
    // Drive the built binary so loadEffectiveConfig runs against on-disk config.
    requireBin();
    const cwd = join(tmp, 'repo');
    mkdirSync(join(cwd, '.chaff'), { recursive: true });
    // A folder-allowlisted var whose name trips a glob → folder-trust warning.
    writeConfig(join(cwd, '.chaff'), { allowlist: ['FOLDER_TOKEN'], declaredManaged: [] });

    const realValue = 'folder-token-sentinel-xyz';
    const { stdout, stderr, status } = runChaffScan({ FOLDER_TOKEN: realValue }, cwd);
    expect(status).toBe(0);
    expect(stdout).toContain('FOLDER_TOKEN');
    // The folder-trust advisory text mentions the folder config review.
    expect(stdout.toLowerCase()).toContain('folder');
    expect(stdout).not.toContain(realValue);
    expect(stderr).not.toContain(realValue);
  });

  it("formatScanReport renders a dropped-var hint advising that a needed dropped var can be added to the allowlist whenever the dropped bucket is non-empty (the 'if cheap' hint is implemented as a static line keyed on dropped.length > 0, naming no value)", () => {
    const report: ScanReport = {
      passthrough: ['PATH'],
      handles: [],
      dropped: ['EDITOR'],
      advisories: [],
      skipped: [],
    };
    const text = formatScanReport(report);
    expect(text).toContain('Advisories:');
    expect(text.toLowerCase()).toContain('allowlist');
  });

  it('when there are no advisories (no allowlisted-secret-looking vars, no folder-trust warnings, empty dropped bucket), formatScanReport emits no advisory section / no stray advisory lines', () => {
    const report: ScanReport = {
      passthrough: ['PATH'],
      handles: ['OPENAI_API_KEY'],
      dropped: [],
      advisories: [],
      skipped: [],
    };
    const text = formatScanReport(report);
    expect(text).not.toContain('Advisories:');
  });
});

describe('ac-4: seeded env + config produces expected names per bucket; no values printed', () => {
  it('given the seeded env {OPENAI_API_KEY (glob secret), PATH (shipped-default allowlist), EDITOR (neither)} and an effective config adding EXTRA_OK to the allowlist and declaring APP_MODE managed, the rendered report lists handles=[APP_MODE, OPENAI_API_KEY], passthrough contains PATH and EXTRA_OK, dropped contains EDITOR — each name appearing exactly once', () => {
    const snapshot = {
      OPENAI_API_KEY: 'sk-glob-secret-sentinel',
      PATH: '/usr/bin:/bin',
      EDITOR: 'vim',
      EXTRA_OK: 'fine',
      APP_MODE: 'production',
    };
    const report = reportFor({
      snapshot,
      allowlist: [...DEFAULT_PASSTHROUGH_ALLOWLIST, 'EXTRA_OK'],
      declaredManaged: ['APP_MODE'],
    });

    expect(report.handles).toEqual(['APP_MODE', 'OPENAI_API_KEY']);
    expect(report.passthrough).toContain('PATH');
    expect(report.passthrough).toContain('EXTRA_OK');
    expect(report.dropped).toContain('EDITOR');

    const text = formatScanReport(report);
    for (const name of Object.keys(snapshot)) {
      expect(text.split(name).length - 1).toBe(1);
    }
  });

  it('given a seeded env whose handle and dropped vars carry known sentinel values, the rendered report string contains none of those sentinel value strings (handle, dropped, and passthrough values are all absent from the output)', () => {
    const snapshot = {
      OPENAI_API_KEY: 'handle-value-sentinel-111',
      EDITOR: 'dropped-value-sentinel-222',
      PATH: 'passthrough-value-sentinel-333',
    };
    const report = reportFor({ snapshot });
    const text = formatScanReport(report);

    for (const value of Object.values(snapshot)) {
      expect(text).not.toContain(value);
    }
  });

  it("`chaff scan` via the built binary with a seeded high-entropy unknown env var reports the var NAME under dropped (DAR-1148: entropy never sources a handle) but never the var's real value on stdout or stderr", () => {
    requireBin();
    const realValue = 'a8Fk2Lp9Qz3Wm7Xb4Vn6Yc1Td5Rg0Hj';
    const { stdout, stderr, status } = runChaffScan({ SCAN_ENTROPY_BLOB: realValue });
    expect(status).toBe(0);

    const lines = stdout.split('\n');
    const hIdx = lines.findIndex((l) => l.includes('Would be replaced by handles:'));
    const dIdx = lines.findIndex((l) => l.includes('Dropped from the harness env:'));
    const aIdx = lines.findIndex((l) => l.includes('Advisories:'));
    const handlesSection = lines.slice(hIdx, dIdx).join('\n');
    const droppedSection = lines.slice(dIdx, aIdx === -1 ? undefined : aIdx).join('\n');
    // Entropy is advisory-only: the high-entropy unknown is dropped, not handled.
    expect(handlesSection).not.toContain('SCAN_ENTROPY_BLOB');
    expect(droppedSection).toContain('SCAN_ENTROPY_BLOB');
    // ...and a name-only advisory flags it as secret-like.
    expect(stdout).toContain('SCAN_ENTROPY_BLOB');
    expect(stdout).not.toContain(realValue);
    expect(stderr).not.toContain(realValue);
  });
});

describe('DAR-1099: scan reports redaction-gate skips (push-scrub OFF), never silent', () => {
  it('buildScanReport yields a NAME-only skip for a handle-secret whose value fails the redaction gate, and none for a strong-valued one', () => {
    const snapshot = {
      WEAK_KEY: 'test', // *_KEY → handle; value fails the gate (short/low-entropy)
      STRONG_KEY: 'a8Fk2Lp9Qz3Wm7Xb4Vn6Yc1Td5Rg0Hj', // *_KEY → handle; clears the gate
    };
    const report = reportFor({ snapshot });

    expect(report.handles).toEqual(['STRONG_KEY', 'WEAK_KEY']);
    expect(report.skipped.map((s) => s.name)).toEqual(['WEAK_KEY']);
    // NAME only — the value never rides along in the skip record.
    for (const skip of report.skipped) {
      expect(JSON.stringify(skip)).not.toContain('test');
    }
  });

  it('--force-scrub overrides the gate for the named secret, so it is no longer reported as a skip', () => {
    const snapshot = { WEAK_KEY: 'test' };
    const report = reportFor({ snapshot, forceScrub: ['WEAK_KEY'] });
    expect(report.skipped).toHaveLength(0);
  });

  it('formatScanReport renders a push-scrub-OFF section naming each skipped secret, value never printed', () => {
    const report: ScanReport = {
      passthrough: ['PATH'],
      handles: ['WEAK_KEY'],
      dropped: [],
      advisories: [],
      skipped: [{ name: 'WEAK_KEY' }],
    };
    const text = formatScanReport(report, report.skipped);
    expect(text.toLowerCase()).toContain('push-scrub off');
    expect(text).toContain('WEAK_KEY');
  });

  it('runScan writes a gated-out secret NAME under push-scrub OFF and never its value', async () => {
    const realValue = 'test'; // *_KEY → handle, but fails the redaction gate
    const chunks: string[] = [];
    const status = await runScan({
      env: { GATED_KEY: realValue, PATH: '/usr/bin' },
      configEnv: {},
      cwd: tmp,
      // No broker in this unit context: pin sockPath empty so the working-tree
      // scan reports skipped rather than depending on an ambient CHAFF_SOCK.
      sockPath: '',
      stdout: { write: (c) => (chunks.push(c), true) },
    });
    const out = chunks.join('');
    expect(status).toBe(0);
    expect(out.toLowerCase()).toContain('push-scrub off');
    expect(out).toContain('GATED_KEY');
  });

  it('`chaff scan` via the built binary reports a gated-out secret NAME under push-scrub OFF, value absent from stdout/stderr', () => {
    requireBin();
    // *_KEY → classified secret (handle), but the value 'short1' fails the gate
    // (below the 8-char min-length floor), so push-scrub is OFF for it.
    const realValue = 'short1';
    const { stdout, stderr, status } = runChaffScan({ BANNER_GATE_KEY: realValue });
    expect(status).toBe(0);
    expect(stdout.toLowerCase()).toContain('push-scrub off');
    expect(stdout).toContain('BANNER_GATE_KEY');
    expect(stdout).not.toContain(realValue);
    expect(stderr).not.toContain(realValue);
  });
});

describe('guard: scan is a pure dry-run — starts no broker, binds no socket', () => {
  it('`chaff scan` via the built binary, given a controlled XDG_RUNTIME_DIR, leaves it empty: no broker session dir or socket is created (regression guard for the DAR-1098 dry-run property — buildScanReport calls buildHarnessEnv but never startBroker)', () => {
    requireBin();
    const runtimeDir = join(tmp, 'runtime');
    mkdirSync(runtimeDir, { recursive: true });

    // Seed a *_KEY glob-secret so the build path does real work (mints a handle).
    const { stdout, status } = runChaffScan({
      XDG_RUNTIME_DIR: runtimeDir,
      SCAN_GUARD_KEY: 'sk-scan-guard-secret',
    });

    expect(status).toBe(0);
    expect(stdout).toContain('SCAN_GUARD_KEY'); // the report was actually produced

    // The broker is the only component that binds a socket; it places its 0700
    // session dir + 0600 socket under XDG_RUNTIME_DIR. Scan must start no broker,
    // so the dir stays empty. A regression that made scan start the broker (e.g.
    // buildScanReport gaining a startBroker call) would leave an entry here.
    expect(readdirSync(runtimeDir)).toEqual([]);
  });
});

describe('DAR-1106: chaff scan working-tree secret scan (detective control)', () => {
  let broker: Broker | undefined;

  afterEach(() => {
    broker?.close();
    broker = undefined;
  });

  // Drive runScan in-process so the same process hosts both the broker and the
  // scan: runScan is async, so it yields to the event loop and the broker can
  // service the tree-scan's redaction-set fetch over CHAFF_SOCK. (Spawning the
  // built bin while the broker lives in this synchronous test process would
  // deadlock — execFileSync blocks the event loop the broker accepts on.) This
  // is still the scan code path end-to-end: a real broker socket fetch, a real
  // tree grep, and the real report writer.
  async function scanCwd(args: {
    cwd: string;
    sockPath: string | undefined;
  }): Promise<{ stdout: string; status: number }> {
    const chunks: string[] = [];
    const status = await runScan({
      env: {},
      configEnv: {},
      cwd: args.cwd,
      sockPath: args.sockPath,
      stdout: { write: (c) => (chunks.push(c), true) },
    });
    return { stdout: chunks.join(''), status };
  }

  it("the working-tree scan obtains its known values from the broker redaction-set op via CHAFF_SOCK (given a running broker holding a secret, scanning a tree containing that secret's value flags the file); when CHAFF_SOCK is unset it reports that the tree scan was skipped rather than crashing", async () => {
    const secret = 'sk-WORKTREE-INTEG-0123456789abcdef';
    broker = await startBroker({
      secrets: [{ name: 'API_KEY', value: secret, handle: 'chaff:1:API_KEY:0123456789ab' }],
      auditLogPath: join(tmp, 'audit.jsonl'),
    });

    const tree = join(tmp, 'tree');
    mkdirSync(join(tree, 'sub'), { recursive: true });
    writeFileSync(join(tree, 'sub', 'leaked.txt'), `key=${secret}\n`, 'utf8');

    // With CHAFF_SOCK pointing at the broker, scanning that tree flags the file
    // by location — and never prints the secret value.
    const withSock = await scanCwd({ cwd: tree, sockPath: broker.sockPath });
    expect(withSock.status).toBe(0);
    expect(withSock.stdout).toContain('leaked.txt');
    expect(withSock.stdout).not.toContain(secret);

    // Without CHAFF_SOCK the tree scan is skipped (no broker to fetch values
    // from), reported as a skip rather than crashing; still exits 0.
    const noSock = await scanCwd({ cwd: tree, sockPath: '' });
    expect(noSock.status).toBe(0);
    expect(noSock.stdout.toLowerCase()).toContain('skipped');
  });

  it('the working-tree scan emits a detective warning (not a preventive deny/error) and chaff scan still exits 0 when a planted secret is found — it warns, it does not block', async () => {
    const secret = 'sk-WORKTREE-DETECTIVE-0123456789ab';
    broker = await startBroker({
      secrets: [{ name: 'API_KEY', value: secret, handle: 'chaff:1:API_KEY:0123456789ab' }],
      auditLogPath: join(tmp, 'audit.jsonl'),
    });
    const tree = join(tmp, 'tree');
    mkdirSync(tree, { recursive: true });
    writeFileSync(join(tree, 'app.env'), `API_KEY=${secret}\n`, 'utf8');

    const { stdout, status } = await scanCwd({ cwd: tree, sockPath: broker.sockPath });
    // Detective: warns, exits 0 (does not deny/block).
    expect(status).toBe(0);
    expect(stdout.toLowerCase()).toMatch(/warn/);
    expect(stdout).toContain('app.env');
  });

  it('chaff scan working-tree mode over a temp dir containing a file with a planted known redaction value flags that file (planted-secret detection), exercised through the scan code path end-to-end', async () => {
    const secret = 'sk-WORKTREE-PLANTED-0123456789abcd';
    broker = await startBroker({
      secrets: [{ name: 'TOKEN', value: secret, handle: 'chaff:1:TOKEN:0123456789ab' }],
      auditLogPath: join(tmp, 'audit.jsonl'),
    });
    const tree = join(tmp, 'tree');
    mkdirSync(join(tree, 'nested'), { recursive: true });
    writeFileSync(join(tree, 'nested', 'planted.json'), `{"token":"${secret}"}\n`, 'utf8');

    const { stdout, status } = await scanCwd({ cwd: tree, sockPath: broker.sockPath });
    expect(status).toBe(0);
    expect(stdout).toContain('planted.json');
    expect(stdout).not.toContain(secret);
  });
});
