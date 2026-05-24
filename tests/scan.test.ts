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
import { existsSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { classify } from '../src/policy.js';
import { buildHarnessEnv, DEFAULT_PASSTHROUGH_ALLOWLIST } from '../src/launcher.js';
import { type LevelConfig } from '../src/config.js';
import { buildScanReport, formatScanReport, type ScanReport } from '../src/scan.js';
import { writeConfig } from './helpers/config-seed.js';

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const BIN = join(SRC_DIR, '..', 'dist', 'bin', 'chaff.js');

/** Build a scan report from a snapshot under the given effective config. */
function reportFor(args: {
  snapshot: Record<string, string>;
  allowlist?: readonly string[];
  declaredManaged?: readonly string[];
  configWarnings?: readonly string[];
}): ScanReport {
  return buildScanReport({
    snapshot: args.snapshot,
    classification: classify(args.snapshot, {}),
    allowlist: args.allowlist ?? DEFAULT_PASSTHROUGH_ALLOWLIST,
    declaredManaged: args.declaredManaged,
    configWarnings: args.configWarnings,
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
function runChaffScan(extraEnv: Record<string, string>, cwd?: string): {
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

  it("the entropy-vs-allowlist precedence carve-out is honored by scan because it shares buildHarnessEnv: an allowlisted var whose value trips ONLY the entropy backstop is reported as passthrough (not handle), matching buildHarnessEnv's behavior", () => {
    // A long high-entropy value on an allowlisted name: entropy backstop fires,
    // but the explicit allowlist entry wins → passthrough.
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

  it("`chaff scan` via the built binary with a seeded high-entropy secret env var emits the var NAME in stdout under handles but never the var's real value on stdout or stderr", () => {
    requireBin();
    const realValue = 'a8Fk2Lp9Qz3Wm7Xb4Vn6Yc1Td5Rg0Hj';
    const { stdout, stderr, status } = runChaffScan({ SCAN_ENTROPY_BLOB: realValue });
    expect(status).toBe(0);

    const lines = stdout.split('\n');
    const hIdx = lines.findIndex((l) => l.includes('Would be replaced by handles:'));
    const dIdx = lines.findIndex((l) => l.includes('Dropped from the harness env:'));
    const handlesSection = lines.slice(hIdx, dIdx).join('\n');
    expect(handlesSection).toContain('SCAN_ENTROPY_BLOB');
    expect(stdout).not.toContain(realValue);
    expect(stderr).not.toContain(realValue);
  });
});
