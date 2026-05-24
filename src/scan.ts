/**
 * Layer A `chaff scan` — the classification dry-run report.
 *
 * A trust-building preview of what `chaff run` would do, without launching
 * anything: it snapshots the current env, runs the same {@link classify} path
 * the launcher uses, and prints which vars would be replaced by handles vs.
 * which pass through unchanged. It never emits a secret VALUE, never starts a
 * broker, and never spawns a process — it only reads and reports.
 *
 * The pure core ({@link buildScanReport}, {@link formatScanReport}) is split
 * from the I/O orchestration ({@link runScan}) so the partitioning and
 * rendering logic are unit-testable without touching `process.env` or stdout —
 * mirroring the launcher's split (DAR-1100).
 *
 * Redaction-gate skip reporting (DAR-1099, Phase 3) and the working-tree secret
 * scan plus `--strict-reads` (DAR-1106, Phase 4) extend this command later and
 * are deliberately out of scope here.
 */

import { classify, type Classification, type EnvSnapshot } from './policy.js';

/** A var-name partition of an env snapshot's classification. */
export interface ScanReport {
  /** Names that would be replaced by handles (classified secret). Sorted. */
  handles: string[];
  /** Names that pass through unchanged (classified non-secret). Sorted. */
  passThrough: string[];
}

/**
 * Partition a classification into the names that would be replaced by handles
 * vs. the names that pass through unchanged. Pure: derives its result solely
 * from `classification`. Each input name lands in exactly one group; both
 * groups are sorted for a stable report.
 */
export function buildScanReport(classification: Classification): ScanReport {
  const handles: string[] = [];
  const passThrough: string[] = [];

  for (const [name, verdict] of Object.entries(classification)) {
    if (verdict.secret) {
      handles.push(name);
    } else {
      passThrough.push(name);
    }
  }

  handles.sort();
  passThrough.sort();
  return { handles, passThrough };
}

/**
 * Render the scan report as text: secret names under a "would be replaced by
 * handles" grouping, non-secret names under a "passes through unchanged"
 * grouping. Only NAMES appear — never a value. Each name appears exactly once.
 *
 * Structured as discrete lines so the redaction-gate skip line (DAR-1099,
 * Phase 3) and the working-tree scan section (DAR-1106, Phase 4) can be
 * appended later without reworking this format.
 */
export function formatScanReport(report: ScanReport): string {
  const lines = ['chaff scan: classification dry-run (no harness or broker is started)', ''];

  lines.push('Would be replaced by handles:');
  if (report.handles.length === 0) {
    lines.push('  (none)');
  } else {
    for (const name of report.handles) {
      lines.push(`  ${name}`);
    }
  }

  lines.push('');
  lines.push('Passes through unchanged:');
  if (report.passThrough.length === 0) {
    lines.push('  (none)');
  } else {
    for (const name of report.passThrough) {
      lines.push(`  ${name}`);
    }
  }

  return lines.join('\n') + '\n';
}

/** A minimal stdout sink — `process.stdout` satisfies this. */
export interface StdoutSink {
  write(chunk: string): boolean;
}

/** Inputs to {@link runScan}. */
export interface ScanOptions {
  /** Env snapshot to classify. Defaults to a copy of `process.env`. */
  env?: EnvSnapshot;
  /** Where the report is written. Defaults to `process.stdout`. */
  stdout?: StdoutSink;
}

/** Snapshot `process.env` into a plain string map (dropping undefined values). */
function snapshotProcessEnv(): EnvSnapshot {
  const snapshot: EnvSnapshot = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (value !== undefined) {
      snapshot[name] = value;
    }
  }
  return snapshot;
}

/**
 * Run the `chaff scan` dry-run and return its exit code (always 0 — scan never
 * fails on classification alone). Snapshots the env, classifies it with the
 * launcher's default policy (`classify(snapshot, {})`), and writes the report
 * to stdout. Starts no broker and spawns no process.
 */
export function runScan(options: ScanOptions = {}): number {
  const snapshot = options.env ?? snapshotProcessEnv();
  const stdout = options.stdout ?? process.stdout;

  const classification = classify(snapshot, {});
  stdout.write(formatScanReport(buildScanReport(classification)));
  return 0;
}
