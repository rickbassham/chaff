/**
 * Layer A launcher — the `chaff run -- <harness cmd>` entry point.
 *
 * Ties policy + broker + handles together (PLAN.md "Layer A"):
 *
 *   1. snapshot the env at invocation time,
 *   2. classify each var via {@link classify},
 *   3. build a harness env where every secret value is replaced by a
 *      {@link formatHandle} handle and `CHAFF_SOCK` points at the broker socket,
 *   4. start the in-process {@link startBroker broker} holding the real values,
 *   5. print the launch banner of handled var names to stderr,
 *   6. spawn the harness with the handle env,
 *   7. tear the broker down when the harness exits, propagating its exit code.
 *
 * The broker (not the harness env) holds the real values; the harness only ever
 * sees handles plus the socket path. Handle resolution back into a child env is
 * `chaff exec` (DAR-1101, Phase 2) and is deliberately out of scope here.
 *
 * The pure core ({@link buildHarnessEnv}, {@link formatLaunchBanner}) is split
 * from the I/O orchestration ({@link runLauncher}) so the env-building and
 * banner logic are unit-testable without spawning a process or a broker.
 */

import { spawn } from 'node:child_process';
import { constants, homedir } from 'node:os';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { formatHandle } from './handles.js';
import { classify, type Classification, type EnvSnapshot } from './policy.js';
import { startBroker, type BrokerSecret } from './broker.js';

/** The result of turning an env snapshot into a harness env. */
export interface HarnessEnvBuild {
  /**
   * The env to hand the harness: every secret var's value replaced by its
   * handle, every non-secret var passed through unchanged, plus `CHAFF_SOCK`.
   */
  env: Record<string, string>;
  /** One {@link BrokerSecret} per secret var, to seed the broker with. */
  secrets: BrokerSecret[];
}

/**
 * Build the harness env and the broker's secret list from a snapshot and its
 * classification. Pure: takes the snapshot by value (the returned env is a fresh
 * object), so mutating the caller's snapshot afterward never changes the result.
 *
 * For each var: if classified secret, mint a handle for its NAME, put the handle
 * in the env, and record a {@link BrokerSecret} carrying the real value. Other
 * vars pass through unchanged. `CHAFF_SOCK` is set to `sockPath` — the only
 * extra key, and never a secret value or auth token.
 */
export function buildHarnessEnv(
  snapshot: EnvSnapshot,
  classification: Classification,
  sockPath: string,
): HarnessEnvBuild {
  const env: Record<string, string> = {};
  const secrets: BrokerSecret[] = [];

  for (const [name, value] of Object.entries(snapshot)) {
    if (classification[name]?.secret === true) {
      const handle = formatHandle(name);
      env[name] = handle;
      secrets.push({ name, value, handle });
    } else {
      env[name] = value;
    }
  }

  env.CHAFF_SOCK = sockPath;
  return { env, secrets };
}

/**
 * Render the launch banner: which vars became handles, by NAME only (never a
 * value). Written to stderr by {@link runLauncher} so it cannot contaminate the
 * harness's stdout.
 *
 * Structured as discrete lines so the redaction-gate skip line ("push-scrub OFF
 * for X") can be appended when that gate lands (DAR-1099, Phase 3) without
 * reworking this format.
 */
export function formatLaunchBanner(classification: Classification): string {
  const handled = Object.keys(classification)
    .filter((name) => classification[name]!.secret)
    .sort();

  const lines = ['chaff: launching harness with secret values replaced by handles'];
  if (handled.length === 0) {
    lines.push('  (no vars classified as secret)');
  } else {
    for (const name of handled) {
      lines.push(`  handle: ${name}`);
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

  // Build env + secrets ONCE so the handles seeded into the broker are the very
  // same strings placed in the harness env — a second build would mint fresh
  // nonces and the broker could not resolve the env's handles. CHAFF_SOCK is the
  // only field that depends on the (not-yet-known) sockPath; patch it in after
  // the broker starts rather than rebuilding.
  const { env, secrets } = buildHarnessEnv(snapshot, classification, '');

  return startBroker({ secrets, auditLogPath: options.auditLogPath }).then((broker) => {
    env.CHAFF_SOCK = broker.sockPath;
    stderr.write(formatLaunchBanner(classification));

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
