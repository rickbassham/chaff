/**
 * Layer A `chaff scan` — the default-deny dry-run report (DAR-1141).
 *
 * A trust-building preview of what `chaff run` would do, without launching
 * anything: it snapshots the current env, loads the *effective* allowlist +
 * managed-secret config (defaults → user → folder via {@link loadEffectiveConfig},
 * DAR-1140), and reports — by NAME only, never a value — which vars would
 * **pass through**, become **handles**, or be **dropped** under the default-deny
 * model (DAR-1139).
 *
 * The bucketing is computed by reusing {@link buildHarnessEnv}, the very code
 * path the launcher uses — there is no divergent second classifier, so the
 * report and the launcher can never disagree. The env and broker secrets
 * `buildHarnessEnv` produces are discarded here; scan starts no broker, binds no
 * socket, and spawns nothing — it only reads and reports.
 *
 * Advisories surfaced (names only, never values): allowlisted-but-secret-looking
 * vars (the precedence-rule warnings `buildHarnessEnv` emits), folder-trust
 * warnings carried through from {@link loadEffectiveConfig}, and — when the
 * dropped bucket is non-empty — a static hint that a needed-but-dropped var can
 * be added to the allowlist.
 *
 * The pure core ({@link buildScanReport}, {@link formatScanReport}) is split
 * from the I/O orchestration ({@link runScan}) so the partitioning and rendering
 * logic are unit-testable without touching `process.env` or stdout — mirroring
 * the launcher's split (DAR-1100).
 *
 * Redaction-gate skip reporting (DAR-1099, Phase 3) and the working-tree secret
 * scan plus `--strict-reads` (DAR-1106, Phase 4) extend this command later and
 * are deliberately out of scope here.
 */

import { classify, type Classification, type EnvSnapshot } from './policy.js';
import {
  buildHarnessEnv,
  DEFAULT_PASSTHROUGH_ALLOWLIST,
  type HarnessEnvBuild,
} from './launcher.js';
import { loadEffectiveConfig } from './config.js';

/**
 * A var-name partition of an env snapshot under the default-deny model: the
 * three buckets the launcher would actually produce, plus advisory warnings.
 * Names only — never a value.
 */
export interface ScanReport {
  /** Names passed through verbatim (allowlisted, not a managed secret). Sorted. */
  passthrough: string[];
  /** Names replaced by handles (detected-secret ∪ declared-managed). Sorted. */
  handles: string[];
  /** Names dropped entirely (neither allowlisted nor a managed secret). Sorted. */
  dropped: string[];
  /**
   * Advisory warnings (by NAME, never a value): the precedence-rule warnings
   * {@link buildHarnessEnv} emits for allowlisted-but-secret-looking vars, plus
   * any folder-trust warnings carried through from the effective config. The
   * needed-but-dropped allowlist hint is NOT here — it is a static line
   * {@link formatScanReport} renders when the dropped bucket is non-empty.
   */
  advisories: string[];
}

/** Inputs to {@link buildScanReport}. */
export interface BuildScanReportOptions {
  /** The env snapshot to sort into buckets. */
  snapshot: EnvSnapshot;
  /** The advisory classification (from {@link classify}) identifying detected secrets. */
  classification: Classification;
  /** The effective passthrough allowlist (literal names and `*`-globs). */
  allowlist: readonly string[];
  /** Names explicitly declared as managed secrets. Defaults to empty. */
  declaredManaged?: readonly string[];
  /**
   * Extra advisory warnings to fold in alongside the build's own (e.g. the
   * folder-trust warnings from {@link loadEffectiveConfig}). Defaults to empty.
   */
  configWarnings?: readonly string[];
}

/**
 * Partition a snapshot into the three default-deny buckets — passthrough,
 * handle, dropped — by reusing {@link buildHarnessEnv}, the same bucketing the
 * launcher uses (single source of truth, no divergent second classifier). The
 * env and broker secrets `buildHarnessEnv` produces are discarded; only its
 * bucket lists and advisory warnings are reported. Pure: derives its result
 * solely from its arguments.
 *
 * Because the buckets flow through `buildHarnessEnv`, scan inherits its
 * precedence rules verbatim: handle-over-passthrough (an allowlisted var that is
 * also a name-glob/declared-managed secret is reported as a handle), and the
 * entropy-vs-allowlist carve-out (an allowlisted var tripping only the entropy
 * backstop passes through). The advisories combine `buildHarnessEnv`'s own
 * precedence-rule warnings with any `configWarnings` (folder-trust) passed in.
 */
export function buildScanReport(options: BuildScanReportOptions): ScanReport {
  const build: HarnessEnvBuild = buildHarnessEnv({
    snapshot: options.snapshot,
    classification: options.classification,
    allowlist: options.allowlist,
    declaredManaged: options.declaredManaged,
    // A dummy sock path: scan discards the built env and never starts a broker,
    // so CHAFF_SOCK's value is irrelevant — it is not reported.
    sockPath: '',
  });

  return {
    passthrough: build.passthrough,
    handles: build.handles,
    dropped: build.dropped,
    advisories: [...build.warnings, ...(options.configWarnings ?? [])],
  };
}

/**
 * Render the scan report as text: a passthrough section, a handle section, and
 * a dropped section, each labeled. Only NAMES appear — never a value. Each input
 * var name appears exactly once across the three sections.
 *
 * An advisory section is rendered when there is anything to advise: any
 * {@link ScanReport.advisories} entry, or a non-empty dropped bucket. The
 * needed-but-dropped allowlist hint is a single static line keyed on
 * `dropped.length > 0` (the AC's "if cheap" qualifier — it names no specific var
 * and computes nothing per-var). When there are no advisories and the dropped
 * bucket is empty, no advisory section is emitted.
 *
 * Structured as discrete lines so the redaction-gate skip line (DAR-1099,
 * Phase 3) and the working-tree scan section (DAR-1106, Phase 4) can be
 * appended later without reworking this format.
 */
export function formatScanReport(report: ScanReport): string {
  const lines = [
    'chaff scan: default-deny dry-run (no harness or broker is started)',
    '',
  ];

  appendSection(lines, 'Passes through unchanged:', report.passthrough);
  lines.push('');
  appendSection(lines, 'Would be replaced by handles:', report.handles);
  lines.push('');
  appendSection(lines, 'Dropped from the harness env:', report.dropped);

  const hasDroppedHint = report.dropped.length > 0;
  if (report.advisories.length > 0 || hasDroppedHint) {
    lines.push('');
    lines.push('Advisories:');
    for (const advisory of report.advisories) {
      lines.push(`  ${advisory}`);
    }
    if (hasDroppedHint) {
      lines.push(
        '  A needed var that was dropped can be added to the passthrough allowlist (user or folder .chaff config).',
      );
    }
  }

  return lines.join('\n') + '\n';
}

/** Append a labeled section listing `names` (or `(none)` when empty). */
function appendSection(lines: string[], label: string, names: string[]): void {
  lines.push(label);
  if (names.length === 0) {
    lines.push('  (none)');
  } else {
    for (const name of names) {
      lines.push(`  ${name}`);
    }
  }
}

/** A minimal stdout sink — `process.stdout` satisfies this. */
export interface StdoutSink {
  write(chunk: string): boolean;
}

/** Inputs to {@link runScan}. */
export interface ScanOptions {
  /** Env snapshot to classify into buckets. Defaults to a copy of `process.env`. */
  env?: EnvSnapshot;
  /** Where the report is written. Defaults to `process.stdout`. */
  stdout?: StdoutSink;
  /**
   * Working directory whose `./.chaff` is the folder-level config (DAR-1140).
   * Defaults to `process.cwd()`.
   */
  cwd?: string;
  /**
   * Env used to resolve the user-level config location
   * (`$XDG_CONFIG_HOME/chaff` → `~/.config/chaff`). Defaults to `process.env`.
   * Separate from `env` (the snapshot bucketed in the report) so a caller can
   * point config discovery at fixtures without altering the reported env.
   */
  configEnv?: EnvSnapshot;
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
 * fails on classification alone). Snapshots the env, loads the effective
 * allowlist + declared-managed config (defaults → user → folder), buckets the
 * snapshot by reusing {@link buildHarnessEnv}, and writes the report to stdout.
 * Starts no broker and spawns no process.
 */
export function runScan(options: ScanOptions = {}): number {
  const snapshot = options.env ?? snapshotProcessEnv();
  const stdout = options.stdout ?? process.stdout;

  const effective = loadEffectiveConfig({
    defaults: DEFAULT_PASSTHROUGH_ALLOWLIST,
    configEnv: options.configEnv ?? snapshotProcessEnv(),
    cwd: options.cwd ?? process.cwd(),
    snapshot,
  });

  const classification = classify(snapshot, {});
  const report = buildScanReport({
    snapshot,
    classification,
    allowlist: effective.allowlist,
    declaredManaged: effective.declaredManaged,
    configWarnings: effective.warnings,
  });
  stdout.write(formatScanReport(report));
  return 0;
}
