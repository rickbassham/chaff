/**
 * Layer B `chaff exec --b64 <blob>` — resolve handles into a child env, then run
 * the decoded command (PLAN.md "Layer B", decision #2).
 *
 * The PreToolUse hook (DAR-1104) rewrites every Bash tool call into
 * `chaff exec --b64 '<base64(originalCommand)>'`. This command is the consumer:
 * it base64-decodes the original command, connects to the broker via
 * `CHAFF_SOCK`, resolves every handle-valued env var into its real value **in
 * the child environment only**, and runs the decoded command under an inner
 * shell with `-c`.
 *
 * Why base64 (decision #2): the harness re-parses `updatedInput.command` through
 * a shell before chaff sees it. Passing the raw command would let the harness
 * shell split pipes/quotes/redirects and expand `$VAR` against the harness env —
 * which holds only handles — so `tool --key $SECRET` would receive the handle
 * text and fail. Base64-wrapping defers BOTH shell-parsing AND `$VAR` expansion
 * to the inner shell {@link INNER_SHELL} we spawn here, which has the real values
 * in its env. So the decoded string is handed to `bash -c` verbatim; chaff never
 * parses the command's shell syntax itself.
 *
 * Why bash (decision #2 open sub-decision): the inner shell is `bash`, not
 * `$SHELL`/`sh`. LLMs tend to write bash-isms, and matching the shell the harness
 * itself runs Bash tool calls under gives identical end-to-end semantics. PLAN.md
 * says "lean bash; confirm at Phase 4" — this lands the bash lean and keeps it
 * consistent via the single {@link INNER_SHELL} constant. It MUST stay consistent
 * with the harness's Bash shell; do not re-derive it per call site.
 *
 * Trust boundary: the parent/harness env carries only handles. Resolution writes
 * real values into a fresh child env object handed to {@link spawn}; the parent's
 * own `process.env` is never mutated, so the harness keeps only handles.
 *
 * Output scrubbing/redaction of the child's stdout/stderr is DAR-1102 (Phase 3)
 * and is deliberately out of scope here — exec emits the child's raw bytes.
 */

import { spawn, type StdioOptions } from 'node:child_process';
import { createConnection } from 'node:net';
import { constants } from 'node:os';
import { isHandle } from './handles.js';
import type { EnvSnapshot } from './policy.js';

/**
 * The inner shell `chaff exec` spawns the decoded command under, with `-c`.
 * Single source of truth (decision #2): defined once so every spawn path uses
 * the same shell rather than re-deriving it. Bash matches the shell the harness
 * runs Bash tool calls under, giving identical end-to-end semantics for the
 * bash-isms LLMs tend to write. Keep this consistent with the harness shell.
 */
export const INNER_SHELL = 'bash';

/** Resolve a single handle to its real value over the broker socket. */
export type HandleResolver = (handle: string) => Promise<string>;

/**
 * Connect to the broker at `sockPath`, send one `resolve` request for `handle`,
 * and resolve with the real value. Uses the broker's newline-delimited JSON wire
 * protocol (broker.ts): write one request line, read one response line. Rejects
 * if the broker returns an `{error}` instead of a `{value}`.
 */
export function resolveViaBroker(sockPath: string, handle: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const conn = createConnection(sockPath);
    let buf = '';
    conn.on('error', reject);
    conn.on('connect', () => {
      conn.write(JSON.stringify({ op: 'resolve', handle }) + '\n');
    });
    conn.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl === -1) {
        return;
      }
      const line = buf.slice(0, nl);
      // Fully tear the socket down (not just half-close) so it leaves no handle
      // keeping exec's event loop alive after resolution completes.
      conn.destroy();
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch (err) {
        reject(err as Error);
        return;
      }
      const res = parsed as { value?: unknown; error?: unknown };
      if (typeof res.value === 'string') {
        resolve(res.value);
        return;
      }
      reject(new Error(typeof res.error === 'string' ? res.error : 'broker resolve failed'));
    });
  });
}

/**
 * Build the CHILD env from an inbound snapshot by replacing every handle-valued
 * var with its broker-resolved real value, leaving non-handle vars unchanged.
 *
 * Pure with respect to the parent: returns a fresh object and never mutates
 * `snapshot`, so the harness/parent env keeps only handles (the resolved real
 * values live solely in the returned child env). A var whose value is not a
 * handle ({@link isHandle} false) is copied through verbatim.
 */
export async function resolveChildEnv(
  snapshot: EnvSnapshot,
  resolve: HandleResolver,
): Promise<Record<string, string>> {
  const entries = await Promise.all(
    Object.entries(snapshot).map(
      async ([name, value]) => [name, isHandle(value) ? await resolve(value) : value] as const,
    ),
  );
  return Object.fromEntries(entries);
}

/** Inputs to {@link runExec}. */
export interface ExecOptions {
  /** The args after the `exec` command — expected to be `['--b64', '<blob>']`. */
  args: string[];
  /**
   * Inbound env snapshot to resolve handles from. Defaults to a copy of
   * `process.env`. The resolved real values are written only into the spawned
   * child's env, never back into this snapshot.
   */
  env?: EnvSnapshot;
  /**
   * The broker socket path. Defaults to `process.env.CHAFF_SOCK`. When unset,
   * {@link runExec} fails loudly rather than passing handles through unresolved.
   */
  sockPath?: string;
  /**
   * The child's stdio configuration, passed to {@link spawn}. Defaults to
   * `'inherit'` so the decoded command reads/writes the same streams as the
   * harness Bash call it replaces (output scrubbing of those streams is DAR-1102,
   * Phase 3). Tests that capture results via files pass `'ignore'` to avoid
   * coupling the child to the test runner's own stdio.
   */
  stdio?: StdioOptions;
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

/** Parse `['--b64', '<blob>']` into the decoded command string, or throw. */
export function decodeCommand(args: string[]): string {
  const [flag, blob, ...rest] = args;
  if (flag !== '--b64') {
    throw new Error("chaff exec: expected '--b64 <base64>'");
  }
  if (blob === undefined || rest.length > 0) {
    throw new Error("chaff exec: '--b64' takes exactly one base64 blob argument");
  }
  return Buffer.from(blob, 'base64').toString('utf8');
}

/**
 * Run `chaff exec --b64 <blob>` and resolve with the child's exit code.
 *
 * Decodes the base64 blob into the original command, connects to the broker at
 * `CHAFF_SOCK`, resolves every handle-valued env var into the CHILD env, and
 * spawns `bash -c <decodedCommand>` with that child env (stdio inherited). The
 * decoded string is handed to the inner shell verbatim, so the inner shell — not
 * chaff — parses `$VAR`/pipes/quotes/redirects, against the resolved child env.
 *
 * Fails loudly (rejects) when `CHAFF_SOCK` is unset rather than silently passing
 * handles through. The child's exit code is propagated (128+signum when the
 * child is killed by a signal, mirroring shell convention).
 */
export function runExec(options: ExecOptions): Promise<number> {
  const command = decodeCommand(options.args);
  const snapshot = options.env ?? snapshotProcessEnv();
  const sockPath = options.sockPath ?? process.env.CHAFF_SOCK;

  if (sockPath === undefined || sockPath.length === 0) {
    return Promise.reject(
      new Error(
        'chaff exec: CHAFF_SOCK is not set — cannot resolve handles (run under `chaff run`)',
      ),
    );
  }

  return resolveChildEnv(snapshot, (handle) => resolveViaBroker(sockPath, handle)).then(
    (childEnv) =>
      new Promise<number>((resolve, reject) => {
        const child = spawn(INNER_SHELL, ['-c', command], {
          env: childEnv,
          stdio: options.stdio ?? 'inherit',
        });
        child.on('error', reject);
        child.on('exit', (code, signal) => {
          if (code !== null) {
            resolve(code);
            return;
          }
          // Killed by a signal: mirror the shell's 128+signum convention so a
          // signalled child still reports non-zero (matches the launcher).
          const signum = signal !== null ? (constants.signals[signal] ?? 0) : 0;
          resolve(128 + signum);
        });
      }),
  );
}
