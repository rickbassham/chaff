/**
 * In-process secret broker over a Unix-domain socket.
 *
 * The launcher (DAR-1100) starts this broker, holding the real secret values,
 * and exports only the socket path (`CHAFF_SOCK`) to the harness. `chaff exec`
 * (DAR-1101) connects to the socket to resolve handles back into real values
 * for the child process's environment.
 *
 * Trust boundary is the filesystem (PLAN.md decision #1): the socket is a
 * `0600` file inside a `0700` per-session directory under `$XDG_RUNTIME_DIR`
 * (falling back to `os.tmpdir()`). Same-uid enforcement comes from the OS;
 * there is deliberately **no peer-credential check** — Node exposes no
 * peer-cred API for AF_UNIX, so one would force a native dependency, and the
 * accidental-leakage threat model does not require it.
 *
 * Protocol: newline-delimited JSON. A client writes one JSON request line and
 * reads one JSON response line. Ops:
 *   - `{op:'resolve', handle}` → `{value}` | `{error}`
 *   - `{op:'list'}`            → `{names}`           (names only, no values)
 *   - `{op:'redaction-set'}`   → `{patterns, handles}` (precomputed)
 *
 * Every `resolve` is audit-logged via audit.ts as `{ts, op, secretName}` —
 * never the secret value. The socket and session dir are removed on explicit
 * {@link Broker.close} and on process exit, so no stale socket or orphan dir
 * is left behind.
 */

import { createServer, type Server, type Socket } from 'node:net';
import { mkdtempSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeAuditEntry } from './audit.js';

/** A secret the broker holds: its name, real value, and substitution handle. */
export interface BrokerSecret {
  /** The env-var name, e.g. `OPENAI_API_KEY`. Returned by `list`, never the value. */
  name: string;
  /** The real secret value. Returned only by `resolve`, keyed on the handle. */
  value: string;
  /** The handle string that stands in for this secret downstream. */
  handle: string;
}

/** Precomputed redaction set the scrubber consumes (PLAN.md decision #3). */
export interface RedactionSet {
  /** Real secret values to redact from output. */
  patterns: string[];
  /** Handle strings whose appearance in output signals a bypassed secret. */
  handles: string[];
}

/** Options for {@link startBroker}. */
export interface BrokerOptions {
  /** The secrets the broker holds for the session. */
  secrets: BrokerSecret[];
  /** Path to the JSONL audit log every `resolve` is appended to. */
  auditLogPath: string;
}

/** A running broker. */
export interface Broker {
  /** Absolute path of the listening Unix-domain socket (`CHAFF_SOCK`). */
  readonly sockPath: string;
  /**
   * The only environment a client needs to reach the broker: `{CHAFF_SOCK}`.
   * Never carries a token or secret value.
   */
  readonly env: { CHAFF_SOCK: string };
  /** Stop listening and remove the socket file and per-session directory. */
  close(): void;
}

/** A single newline-delimited JSON request from a client. */
interface BrokerRequest {
  op?: string;
  handle?: string;
}

/** Resolve the per-session directory's parent: $XDG_RUNTIME_DIR or os.tmpdir(). */
function runtimeRoot(): string {
  const xdg = process.env.XDG_RUNTIME_DIR;
  if (xdg !== undefined && xdg.length > 0) {
    return xdg;
  }
  return tmpdir();
}

/**
 * Start the broker: create the 0700 session dir and 0600 socket, begin
 * listening, register exit-time teardown, and resolve with the running
 * {@link Broker}. Resolves only once the socket is bound and chmod'd, so the
 * returned broker is immediately connectable.
 */
export function startBroker(options: BrokerOptions): Promise<Broker> {
  const { secrets, auditLogPath } = options;

  // Index by handle for resolve; collect names for list; precompute the
  // redaction set once at construction (it never changes for the session).
  const byHandle = new Map<string, BrokerSecret>();
  for (const s of secrets) {
    byHandle.set(s.handle, s);
  }
  const names = secrets.map((s) => s.name);
  const redactionSet: RedactionSet = {
    patterns: secrets.map((s) => s.value),
    handles: secrets.map((s) => s.handle),
  };

  // Create the per-session dir, forcing 0700 regardless of inherited umask.
  // Keep names short: AF_UNIX socket paths have a low length cap (~104 bytes
  // on macOS), so a long $XDG_RUNTIME_DIR plus our segments must still fit.
  const sessionDir = mkdtempSync(join(runtimeRoot(), 'chaff-'));
  chmodSync(sessionDir, 0o700);
  const sockPath = join(sessionDir, 's.sock');

  function handleRequest(req: BrokerRequest): unknown {
    switch (req.op) {
      case 'resolve': {
        const match = req.handle !== undefined ? byHandle.get(req.handle) : undefined;
        if (match === undefined) {
          return { error: 'unknown handle' };
        }
        writeAuditEntry(auditLogPath, { op: 'resolve', secretName: match.name });
        return { value: match.value };
      }
      case 'list':
        return { names };
      case 'redaction-set':
        return { patterns: redactionSet.patterns, handles: redactionSet.handles };
      default:
        return { error: 'unknown op' };
    }
  }

  function onConnection(conn: Socket): void {
    let buf = '';
    conn.setEncoding('utf8');
    conn.on('data', (chunk: string) => {
      buf += chunk;
      let nl = buf.indexOf('\n');
      while (nl !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.length > 0) {
          let response: unknown;
          try {
            response = handleRequest(JSON.parse(line) as BrokerRequest);
          } catch {
            response = { error: 'bad request' };
          }
          conn.write(JSON.stringify(response) + '\n');
        }
        nl = buf.indexOf('\n');
      }
    });
    // A broken client connection must not crash the broker.
    conn.on('error', () => {});
  }

  const server: Server = createServer(onConnection);

  let closed = false;
  function teardown(): void {
    if (closed) {
      return;
    }
    closed = true;
    server.close();
    // Remove the socket and its private session dir. Best-effort: if the dir
    // is already gone, force keeps teardown from throwing on exit.
    rmSync(sessionDir, { recursive: true, force: true });
    process.removeListener('exit', teardown);
  }

  process.on('exit', teardown);

  const broker: Broker = {
    sockPath,
    env: { CHAFF_SOCK: sockPath },
    close: teardown,
  };

  // listen() binds the AF_UNIX socket asynchronously; the socket file only
  // exists once the 'listening' event fires. We chmod it there (forcing 0600
  // over any inherited umask) and resolve only then, so the returned broker is
  // immediately connectable and its socket already carries the right mode.
  return new Promise<Broker>((resolve, reject) => {
    const onStartupError = (err: Error): void => {
      teardown();
      reject(err);
    };
    server.once('error', onStartupError);
    server.listen(sockPath, () => {
      try {
        chmodSync(sockPath, 0o600);
      } catch (err) {
        teardown();
        reject(err as Error);
        return;
      }
      // Past startup: swap the rejecting handler for a no-op so a later server
      // error can't crash the process with an unhandled 'error' event.
      server.removeListener('error', onStartupError);
      server.on('error', () => {});
      resolve(broker);
    });
  });
}
