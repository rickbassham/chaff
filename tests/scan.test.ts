import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { classify } from '../src/policy.js';
import { buildScanReport, formatScanReport } from '../src/scan.js';

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const BIN = join(SRC_DIR, '..', 'dist', 'bin', 'chaff.js');

/**
 * A representative env snapshot: two glob-secrets, two allowlisted pass-through
 * vars, each secret carrying a known sentinel value the report must never emit.
 */
function seededSnapshot(): Record<string, string> {
  return {
    OPENAI_API_KEY: 'sk-secret-openai-sentinel-123',
    DB_TOKEN: 'secret-db-token-sentinel-456',
    PATH: '/usr/bin:/bin',
    EDITOR: 'vim',
  };
}

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-scan-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

/** Run `chaff scan` via the built binary; return {stdout, stderr, status}. */
function runChaffScan(extraEnv: Record<string, string>): {
  stdout: string;
  stderr: string;
  status: number;
} {
  try {
    const stdout = execFileSync(process.execPath, [BIN, 'scan'], {
      encoding: 'utf8',
      env: { ...process.env, ...extraEnv },
    });
    return { stdout, stderr: '', status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
  }
}

describe('ac-1: scan reads env, classifies, partitions handles vs pass-through', () => {
  it("given a seeded env snapshot, the pure report builder partitions every var policy.classify marks secret=true into the 'would be replaced by handles' group and every non-secret var into the 'passes through unchanged' group, with no var missing from or duplicated across the two groups", () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const report = buildScanReport(classification);

    for (const [name, verdict] of Object.entries(classification)) {
      if (verdict.secret) {
        expect(report.handles).toContain(name);
        expect(report.passThrough).not.toContain(name);
      } else {
        expect(report.passThrough).toContain(name);
        expect(report.handles).not.toContain(name);
      }
    }

    // Partition: every input var appears in exactly one group, none duplicated.
    const all = [...report.handles, ...report.passThrough].sort();
    expect(all).toEqual(Object.keys(classification).sort());
    expect(new Set(all).size).toBe(all.length);
  });

  it('the rendered report text names every secret-classified var under the handles section and every non-secret var under the pass-through section (each input var name appears exactly once in the report)', () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const text = formatScanReport(buildScanReport(classification));

    for (const name of Object.keys(classification)) {
      const occurrences = text.split(name).length - 1;
      expect(occurrences).toBe(1);
    }
  });

  it('scan classifies using the same policy.classify path as the launcher: a glob-secret name (e.g. OPENAI_API_KEY), an allowlisted name (e.g. PATH), and an entropy-flagged unrecognized name each land in the section policy.classify dictates', () => {
    const snapshot = {
      OPENAI_API_KEY: 'sk-anything',
      PATH: '/usr/bin:/bin',
      RANDOM_BLOB: 'a8Fk2Lp9Qz3Wm7Xb4Vn6Yc1Td5Rg0Hj',
    };
    const classification = classify(snapshot, {});
    const report = buildScanReport(classification);

    // OPENAI_API_KEY -> glob secret; PATH -> allowlist non-secret; RANDOM_BLOB -> entropy secret.
    expect(classification.OPENAI_API_KEY!.mechanism).toBe('glob');
    expect(classification.PATH!.mechanism).toBe('allowlist');
    expect(classification.RANDOM_BLOB!.mechanism).toBe('entropy');

    expect(report.handles).toContain('OPENAI_API_KEY');
    expect(report.passThrough).toContain('PATH');
    expect(report.handles).toContain('RANDOM_BLOB');
  });

  it("`chaff scan` via the built binary reads its own process env, prints the report to stdout, and exits 0 (no harness or broker is started — the scaffold 'not implemented yet' exit-1 path is gone)", () => {
    if (!existsSync(BIN)) {
      throw new Error(`built binary missing at ${BIN}; run \`make build\` first`);
    }
    const { stdout, status } = runChaffScan({ E2E_SCAN_KEY: 'sk-e2e-scan-secret-abc' });
    expect(status).toBe(0);
    expect(stdout).toContain('E2E_SCAN_KEY');
    expect(stdout).not.toContain('not implemented yet');
  });

  it('`chaff scan` via the built binary does NOT create or bind a unix socket and does NOT spawn a child process (dry-run only: no CHAFF_SOCK side effects, no broker session directory left on disk)', () => {
    if (!existsSync(BIN)) {
      throw new Error(`built binary missing at ${BIN}; run \`make build\` first`);
    }
    const runtimeDir = join(tmp, 'runtime');
    rmSync(runtimeDir, { recursive: true, force: true });
    const { stdout, status } = runChaffScan({
      E2E_SCAN_KEY: 'sk-e2e-scan-secret-def',
      XDG_RUNTIME_DIR: runtimeDir,
    });
    expect(status).toBe(0);
    // CHAFF_SOCK is a launcher-only concern; scan must not leak it into stdout.
    expect(stdout).not.toContain('CHAFF_SOCK');
    // A broker would create its session directory under XDG_RUNTIME_DIR; a dry
    // run must leave nothing behind there (the dir should not even be created).
    if (existsSync(runtimeDir)) {
      expect(readdirSync(runtimeDir)).toEqual([]);
    } else {
      expect(existsSync(runtimeDir)).toBe(false);
    }
  });
});

describe('ac-2: scan never prints secret values', () => {
  it('given a seeded env whose secret-classified vars carry known sentinel values, the rendered report string contains none of those secret value strings', () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const text = formatScanReport(buildScanReport(classification));

    for (const [name, verdict] of Object.entries(classification)) {
      if (verdict.secret) {
        expect(text).not.toContain(snapshot[name]);
      }
    }
  });

  it("`chaff scan` via the built binary with a seeded high-entropy secret env var emits the var NAME in its output but never the var's real value on stdout or stderr", () => {
    if (!existsSync(BIN)) {
      throw new Error(`built binary missing at ${BIN}; run \`make build\` first`);
    }
    const realValue = 'a8Fk2Lp9Qz3Wm7Xb4Vn6Yc1Td5Rg0Hj';
    const { stdout, stderr, status } = runChaffScan({ SCAN_ENTROPY_BLOB: realValue });
    expect(status).toBe(0);
    expect(stdout).toContain('SCAN_ENTROPY_BLOB');
    expect(stdout).not.toContain(realValue);
    expect(stderr).not.toContain(realValue);
  });
});

describe('ac-3: report lists expected secret names and omits their values', () => {
  it("given the seeded env {OPENAI_API_KEY, DB_TOKEN (glob secrets), PATH, EDITOR (pass-through)}, the report's handles section lists exactly OPENAI_API_KEY and DB_TOKEN and the report contains neither secret's value", () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const report = buildScanReport(classification);

    expect([...report.handles].sort()).toEqual(['DB_TOKEN', 'OPENAI_API_KEY']);

    const text = formatScanReport(report);
    expect(text).not.toContain(snapshot.OPENAI_API_KEY);
    expect(text).not.toContain(snapshot.DB_TOKEN);
  });

  it('given a seeded env, the report lists every expected pass-through name (PATH, EDITOR) in the pass-through section and lists no pass-through name in the handles section', () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const report = buildScanReport(classification);

    expect(report.passThrough).toContain('PATH');
    expect(report.passThrough).toContain('EDITOR');
    expect(report.handles).not.toContain('PATH');
    expect(report.handles).not.toContain('EDITOR');
  });
});
