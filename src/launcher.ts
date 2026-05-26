/**
 * Layer A launcher — the `chaff run -- <harness cmd>` entry point.
 *
 * Ties policy + broker + handles together (PLAN.md "Layer A") under a
 * **default-deny** posture (decision `chaff_decision_default_deny_env`):
 *
 *   1. snapshot the env at invocation time,
 *   2. classify each var via {@link classify} (now *advisory* — it suggests the
 *      managed set; it is no longer load-bearing for safety),
 *   3. sort each var into exactly one bucket and build the harness env —
 *      **passthrough** (name on the effective allowlist → value verbatim),
 *      **handle** (managed secret = detected-secret ∪ declared-managed →
 *      {@link formatHandle}, real value seeded to the broker), or **dropped**
 *      (neither → absent from the harness env entirely). `CHAFF_SOCK` points at
 *      the broker socket,
 *   4. start the in-process {@link startBroker broker} holding the real values,
 *   5. print the per-bucket launch banner to stderr (passthrough count, handle
 *      names, dropped count, advisory warnings — names only, never values),
 *   6. spawn the harness with the handle env,
 *   7. tear the broker down when the harness exits, propagating its exit code.
 *
 * Fail-safe: a secret the heuristics miss *and* nobody allowlisted is dropped
 * (a tool may break, visibly) — never leaked. The broker (not the harness env)
 * holds the real values; the harness only ever sees handles plus the socket
 * path. Handle resolution back into a child env is `chaff exec` (DAR-1101,
 * Phase 2) and is deliberately out of scope here.
 *
 * The pure core ({@link buildHarnessEnv}, {@link formatLaunchBanner}) is split
 * from the I/O orchestration ({@link runLauncher}) so the env-building and
 * banner logic are unit-testable without spawning a process or a broker.
 *
 * Config loading of the allowlist / managed-secret set (user + folder, with the
 * folder-trust guard) is DAR-1140; `chaff scan` three-bucket reporting is
 * DAR-1141. Both are out of scope here — `declaredManaged` is just a parameter
 * defaulting to empty.
 */

import { spawn } from 'node:child_process';
import { constants, homedir } from 'node:os';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { formatHandle } from './handles.js';
import { classify, looksHighEntropy, type Classification, type EnvSnapshot } from './policy.js';
import { startBroker, type BrokerSecret } from './broker.js';
import { loadEffectiveConfig } from './config.js';
import { buildRedactionSet, type RedactionSkip } from './redaction.js';

/**
 * The default passthrough allowlist: env-var names handed to the harness
 * verbatim under the default-deny model. Entries are either literal names or
 * `*`-globs (only `*` is special, as in policy globs). Anything not matched
 * here and not a managed secret is **dropped** from the harness env.
 *
 * The set is intentionally minimal and benign — terminal/locale/path plumbing a
 * shell and ordinary tools need to function, none of which carries a secret. A
 * name here that also matches a secret-shaped glob (a NAME signal) is still
 * handled, not passed (see the precedence rule in {@link buildHarnessEnv}); a
 * high-entropy *value* alone does not demote it — entropy never sources a handle
 * (DAR-1148). User/folder config extends this set later (DAR-1140); here it is
 * just the shipped default.
 */
export const DEFAULT_PASSTHROUGH_ALLOWLIST: readonly string[] = [
  'PATH',
  'HOME',
  'SHELL',
  'TERM',
  'LANG',
  'LC_*',
  'TZ',
  'TMPDIR',
  'USER',
  'LOGNAME',
  'PWD',
  'XDG_*',
];

/** Convert a single allowlist entry into an anchored regex. Only `*` is special. */
function entryToRegExp(entry: string): RegExp {
  const escaped = entry.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}

/** Build a name-matcher from an allowlist of literal names and `*`-globs. */
function allowlistMatcher(allowlist: readonly string[]): (name: string) => boolean {
  const patterns = allowlist.map(entryToRegExp);
  return (name: string) => patterns.some((re) => re.test(name));
}

/** The result of turning an env snapshot into a harness env (default-deny). */
export interface HarnessEnvBuild {
  /**
   * The env to hand the harness: passthrough vars verbatim, managed-secret vars
   * as handles, plus `CHAFF_SOCK`. Dropped vars are absent entirely (name and
   * value).
   */
  env: Record<string, string>;
  /** One {@link BrokerSecret} per handle var, to seed the broker with. */
  secrets: BrokerSecret[];
  /** Names passed through verbatim (allowlisted, not a managed secret). Sorted. */
  passthrough: string[];
  /** Names replaced by handles (detected-secret ∪ declared-managed). Sorted. */
  handles: string[];
  /** Names dropped entirely (neither allowlisted nor a managed secret). Sorted. */
  dropped: string[];
  /**
   * Advisory warnings (by NAME, never a value): one per
   * allowlisted-but-secret-looking var that was handled rather than passed
   * through (the precedence rule), and one per *dropped* var whose value looks
   * high-entropy (DAR-1148 — entropy is advisory, so a secret-like dropped var
   * is flagged so it is discoverable). The launcher surfaces these in the banner.
   */
  warnings: string[];
}

/** Inputs to {@link buildHarnessEnv}. */
export interface BuildHarnessEnvOptions {
  /** The env snapshot to sort into buckets. Taken by value. */
  snapshot: EnvSnapshot;
  /**
   * The advisory classification (from {@link classify}) used to identify
   * detected secrets. Demoted from load-bearing to advisory: it only suggests
   * the managed set, it never causes a value to pass through.
   */
  classification: Classification;
  /**
   * The effective passthrough allowlist (literal names and `*`-globs). Callers
   * pass {@link DEFAULT_PASSTHROUGH_ALLOWLIST} (optionally extended by config).
   */
  allowlist: readonly string[];
  /**
   * Names explicitly declared as managed secrets, handled even when the
   * detector does not flag them. Defaults to empty — user/folder config
   * plumbing is DAR-1140.
   */
  declaredManaged?: readonly string[];
  /** Value for `CHAFF_SOCK` — the only added key; never a secret or token. */
  sockPath: string;
}

/**
 * Build the harness env and the broker's secret list from a snapshot, under the
 * default-deny model. Pure: takes the snapshot by value (the returned env is a
 * fresh object), so mutating the caller's snapshot afterward never changes the
 * result.
 *
 * Each var lands in exactly one bucket:
 *   - **handle** if it is a managed secret — a NAME signal only: a name-glob
 *     match or a declared-managed entry (DAR-1148: the entropy backstop is a
 *     value-guess, not a name signal, and never sources a handle). Checked FIRST
 *     so an allowlisted-but-secret-looking var is handled, not passed (the
 *     precedence rule) — and an advisory warning naming it (by NAME only) is
 *     emitted.
 *   - **passthrough** if its name matches the effective allowlist → value
 *     verbatim.
 *   - **dropped** otherwise → absent from the harness env (name and value). If
 *     the dropped value looks high-entropy, a name-only advisory is emitted so a
 *     secret-like dropped var is discoverable (never the value).
 *
 * `CHAFF_SOCK` is always set to `sockPath` — the only extra key, never a secret
 * value or auth token, present even when every var is dropped.
 */
export function buildHarnessEnv(options: BuildHarnessEnvOptions): HarnessEnvBuild {
  const { snapshot, classification, allowlist, sockPath } = options;
  const declaredManaged = new Set(options.declaredManaged ?? []);
  const isAllowlisted = allowlistMatcher(allowlist);

  const env: Record<string, string> = {};
  const secrets: BrokerSecret[] = [];
  const passthrough: string[] = [];
  const handles: string[] = [];
  const dropped: string[] = [];
  const warnings: string[] = [];

  for (const [name, value] of Object.entries(snapshot)) {
    const verdict = classification[name];
    const allowlisted = isAllowlisted(name);
    // A handle comes only from a NAME signal: a secret-shaped glob (e.g.
    // `*_TOKEN`) or an explicit declared-managed entry. The entropy backstop is
    // a VALUE-guess, not a name signal (DAR-1148): it never promotes a var to a
    // handle, so a long high-entropy value (a realistic macOS TMPDIR
    // `/var/folders/...`, `LS_COLORS`, a long `GOROOT`) is bucketed by name
    // alone — passthrough if allowlisted, dropped otherwise. Demoting entropy to
    // advisory makes all unknowns consistent (not allowlisted ∧ not a name
    // signal ⇒ dropped) and keeps benign high-entropy values out of the broker
    // and (Phase 3) the redaction set.
    const detectedSecret = verdict?.secret === true && verdict.mechanism !== 'entropy';
    const managed = detectedSecret || declaredManaged.has(name);

    if (managed) {
      // Handle bucket wins over passthrough: never pass a name-signalled secret
      // through. If it was also allowlisted, that is the precedence case — warn.
      const handle = formatHandle(name);
      env[name] = handle;
      secrets.push({ name, value, handle });
      handles.push(name);
      if (allowlisted) {
        warnings.push(
          `${name} is on the passthrough allowlist but looks like a secret — handled instead of passed through`,
        );
      }
    } else if (allowlisted) {
      env[name] = value;
      passthrough.push(name);
    } else {
      // Dropped: absent from the harness env entirely (name and value). If the
      // value looks high-entropy, surface a name-only advisory (DAR-1148) so a
      // dropped secret-like var is discoverable — it fails safe (the tool breaks
      // visibly) rather than silently. Never name the value.
      dropped.push(name);
      if (looksHighEntropy(value)) {
        warnings.push(
          `${name} looks secret-like and was dropped; declare it managed or allowlist it if a tool needs it`,
        );
      }
    }
  }

  env.CHAFF_SOCK = sockPath;
  passthrough.sort();
  handles.sort();
  dropped.sort();
  return { env, secrets, passthrough, handles, dropped, warnings };
}

/**
 * Render the per-bucket launch banner from a {@link buildHarnessEnv} result:
 * passthrough as a COUNT, handles by NAME, dropped as a COUNT, plus any advisory
 * warnings (by NAME). Never emits an env VALUE. Written to stderr by
 * {@link runLauncher} so it cannot contaminate the harness's stdout.
 *
 * Passthrough is count-only by design — only handles are listed by name, so a
 * long benign env does not bury the security-relevant lines, and no passthrough
 * name (which a value could be confused with) is printed.
 *
 * `skipped` (DAR-1099, decision #3) names secrets the redaction-eligibility gate
 * excluded from push-scrubbing. When non-empty, a push-scrub-OFF section names
 * each one (by NAME only — never a value) so the gate's decision is reported
 * loudly, never silent; the handle/pull-channel still applies to them. When
 * empty (or omitted) no such line is rendered.
 */
export function formatLaunchBanner(
  build: HarnessEnvBuild,
  skipped: readonly RedactionSkip[] = [],
): string {
  const lines = ['chaff: building default-deny harness env'];
  lines.push(`  passthrough: ${build.passthrough.length} var(s) passed through verbatim`);

  if (build.handles.length === 0) {
    lines.push('  handles: (none)');
  } else {
    lines.push('  handles (real values held by the broker):');
    for (const name of build.handles) {
      lines.push(`    ${name}`);
    }
  }

  lines.push(`  dropped: ${build.dropped.length} var(s) withheld from the harness env`);

  if (skipped.length > 0) {
    lines.push('  push-scrub OFF (handle still applies; output not scrubbed for):');
    for (const skip of skipped) {
      lines.push(`    ${skip.name}`);
    }
  }

  if (build.warnings.length > 0) {
    lines.push('  advisory:');
    for (const warning of build.warnings) {
      lines.push(`    ${warning}`);
    }
  }

  return lines.join('\n') + '\n';
}

/** A minimal stderr sink — `process.stderr` satisfies this. */
export interface StderrSink {
  write(chunk: string): boolean;
}

/** Inputs to {@link runLauncher}. */
export interface LauncherOptions {
  /** The harness command and its args, i.e. argv after `--`. */
  argv: string[];
  /** Env snapshot to classify. Defaults to a copy of `process.env`. */
  env?: EnvSnapshot;
  /** JSONL audit log path handed to the broker. */
  auditLogPath: string;
  /** Where the launch banner is written. Defaults to `process.stderr`. */
  stderr?: StderrSink;
  /**
   * Working directory whose `./.chaff` is the folder-level config (DAR-1140).
   * Defaults to `process.cwd()`.
   */
  cwd?: string;
  /**
   * Env used to resolve the user-level config location
   * (`$XDG_CONFIG_HOME/chaff` → `~/.config/chaff`). Defaults to `process.env`.
   * Separate from `env` (the snapshot classified into buckets) so a caller can
   * point config discovery at fixtures without altering the launch env.
   */
  configEnv?: EnvSnapshot;
  /**
   * Secret NAMES whose redaction-eligibility gate is overridden so they are
   * push-scrubbed despite failing it — the `--force-scrub NAME` override
   * (DAR-1099, decision #3). Accepts possible output corruption. Defaults to
   * empty.
   */
  forceScrub?: readonly string[];
}

/**
 * Resolve the default broker audit-log path and ensure its directory exists:
 * `$XDG_STATE_HOME/chaff/audit.jsonl`, falling back to
 * `~/.local/state/chaff/audit.jsonl`. The bin entry uses this; tests pass an
 * explicit path instead.
 */
export function defaultAuditLogPath(): string {
  const xdgState = process.env.XDG_STATE_HOME;
  const stateRoot =
    xdgState !== undefined && xdgState.length > 0 ? xdgState : join(homedir(), '.local', 'state');
  const dir = join(stateRoot, 'chaff');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return join(dir, 'audit.jsonl');
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
 * Run the full `chaff run` orchestration and resolve with the harness's exit
 * code. Snapshots the env once at entry, classifies it, starts the broker with
 * the real values, spawns the harness with the handle env (stdio inherited),
 * and tears the broker down when the harness exits — so the broker outlives the
 * harness by nothing and no stale socket is left behind. Teardown never masks
 * the child result: the resolved code is the child's own exit code (128+signal
 * when the child was killed by a signal, mirroring shell convention).
 */
export function runLauncher(options: LauncherOptions): Promise<number> {
  const snapshot = options.env ?? snapshotProcessEnv();
  const stderr = options.stderr ?? process.stderr;

  const classification = classify(snapshot, {});
  const [command, ...args] = options.argv;
  if (command === undefined) {
    // Reject rather than throw synchronously so the Promise<number> signature
    // holds for direct library callers (the bin entry already guards empty argv).
    return Promise.reject(new Error('chaff run: no harness command given after --'));
  }

  // Discover and merge the user + folder config onto the shipped defaults
  // (defaults→user→folder), enforcing the user never-pass set and collecting any
  // folder-trust warnings (DAR-1140). With no config files present this yields
  // the shipped default allowlist and an empty declared-managed set, so the
  // behaviour matches DAR-1139 exactly.
  const effective = loadEffectiveConfig({
    defaults: DEFAULT_PASSTHROUGH_ALLOWLIST,
    configEnv: options.configEnv ?? snapshotProcessEnv(),
    cwd: options.cwd ?? process.cwd(),
    snapshot,
  });

  // Build env + secrets ONCE so the handles seeded into the broker are the very
  // same strings placed in the harness env — a second build would mint fresh
  // nonces and the broker could not resolve the env's handles. CHAFF_SOCK is the
  // only field that depends on the (not-yet-known) sockPath; patch it in after
  // the broker starts rather than rebuilding. The effective allowlist and
  // declared-managed set come from the merged config above.
  const build = buildHarnessEnv({
    snapshot,
    classification,
    allowlist: effective.allowlist,
    declaredManaged: effective.declaredManaged,
    sockPath: '',
  });
  // Surface folder-trust warnings alongside the build's own advisories so the
  // launch banner reports both (names only, never values).
  build.warnings = [...build.warnings, ...effective.warnings];
  const { env, secrets } = build;

  // Build the gated redaction set (DAR-1099, decision #3) over the handled
  // secrets: short/low-entropy values are excluded from push-scrubbing and
  // recorded as skips so the banner can report them (the handle/pull-channel is
  // unaffected). `--force-scrub` overrides the gate per named secret. The
  // streaming scrubber that consumes the set is DAR-1102.
  const gated = buildRedactionSet({ secrets, forceScrub: options.forceScrub });

  return startBroker({ secrets, auditLogPath: options.auditLogPath }).then((broker) => {
    env.CHAFF_SOCK = broker.sockPath;
    stderr.write(formatLaunchBanner(build, gated.skipped));

    return new Promise<number>((resolve, reject) => {
      const child = spawn(command, args, { env, stdio: 'inherit' });
      child.on('error', (err) => {
        broker.close();
        reject(err);
      });
      child.on('exit', (code, signal) => {
        broker.close();
        if (code !== null) {
          resolve(code);
          return;
        }
        // The child was killed by a signal: mirror the shell's 128+signum
        // convention so a signalled harness still reports non-zero.
        const signum = signal !== null ? (constants.signals[signal] ?? 0) : 0;
        resolve(128 + signum);
      });
    });
  });
}
