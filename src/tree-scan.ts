/**
 * Layer D `chaff scan` working-tree secret scan (PLAN.md "Layer D", decision #4
 * partial mitigation; DAR-1106).
 *
 * A **detective** control for the #1 residual gap: a child writes a secret to a
 * file that is then read back through a non-Bash tool, bypassing the egress
 * scrubber. This scan greps the working tree for the broker's known
 * redaction-set values and warns by file LOCATION only — it never blocks, never
 * fails the scan, and never echoes a matched value (a warning that printed the
 * secret would itself leak it). It is detective, not preventive: it reports
 * where a secret already landed on disk; it does not stop the write.
 *
 * The pure tree walk ({@link scanTree}) is split from the broker I/O
 * ({@link fetchRedactionValues}) so the matching logic is unit-testable without a
 * running broker, mirroring the launcher/scan split (DAR-1100/DAR-1141).
 *
 * Known values come from the broker's `redaction-set` op over `CHAFF_SOCK` (the
 * same precomputed pattern set the egress scrubber uses, broker.ts). When
 * `CHAFF_SOCK` is unset there is no broker to ask, so the orchestration
 * ({@link runTreeScan}) reports the tree scan as skipped rather than crashing —
 * `chaff scan` is typically run standalone, with no session broker.
 *
 * Scope (per the approved contract): this greps for the literal known values
 * only. Encoded-variant matching is the egress scrubber's job (DAR-1102/1096)
 * and is deliberately out of scope here.
 */

import { createConnection } from 'node:net';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

/** A working-tree finding: a file whose contents contain a known secret value. */
export interface TreeFinding {
  /** The path of the file that contains a planted value. Never the value itself. */
  path: string;
}

/** Inputs to {@link scanTree}. */
export interface ScanTreeOptions {
  /** Known secret values to grep for (the broker's redaction-set patterns). */
  values: readonly string[];
  /** The root directory to walk. */
  root: string;
}

/**
 * Directory names skipped during the walk: VCS metadata and heavy generated
 * trees. Greping these would be slow and noisy (and `dist`/`node_modules` can
 * contain matches that are not the child's own leak).
 */
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist']);

/**
 * Files larger than this (bytes) are skipped: a detective grep over a huge or
 * binary blob is both slow and unlikely to be the secret-bearing artifact a
 * cooperative child wrote. Keeps the scan a fast advisory, not a full indexer.
 */
const MAX_FILE_BYTES = 5 * 1024 * 1024;

/**
 * Walk `root` and return a finding for every file whose contents contain any of
 * the known `values`. Reports by file location only — a {@link TreeFinding}
 * carries no value. Empty values are ignored (an empty string would "match"
 * everywhere). Read/stat errors on individual entries are swallowed: a detective
 * scan must not crash on an unreadable file. Synchronous and self-contained.
 */
export function scanTree(options: ScanTreeOptions): TreeFinding[] {
  const values = options.values.filter((v) => v.length > 0);
  if (values.length === 0) {
    return [];
  }
  const findings: TreeFinding[] = [];
  walk(options.root, values, findings);
  return findings;
}

/** Recursive directory walk feeding {@link scanTree}. Best-effort, never throws. */
function walk(dir: string, values: readonly string[], findings: TreeFinding[]): void {
  let entries: import('node:fs').Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        walk(full, values, findings);
      }
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    if (fileContainsValue(full, values)) {
      findings.push({ path: full });
    }
  }
}

/** True when the file at `path` contains any of `values`. Best-effort. */
function fileContainsValue(path: string, values: readonly string[]): boolean {
  try {
    if (statSync(path).size > MAX_FILE_BYTES) {
      return false;
    }
    const contents = readFileSync(path, 'utf8');
    return values.some((value) => contents.includes(value));
  } catch {
    return false;
  }
}

/**
 * Render the tree-scan findings as a detective warning section, by file location
 * only — never the matched value. An empty finding list renders the empty string
 * (no warning section), so a clean tree warns about nothing.
 */
export function formatTreeFindings(findings: readonly TreeFinding[]): string {
  if (findings.length === 0) {
    return '';
  }
  const lines = [
    'working-tree scan WARNING: a known secret value was found on disk (detective only — not blocked):',
  ];
  for (const finding of findings) {
    lines.push(`  ${finding.path}`);
  }
  return lines.join('\n') + '\n';
}

/**
 * Milliseconds the broker fetch waits for a complete newline-terminated response
 * before giving up. A detective scan that hangs indefinitely is worse than one
 * that skips, so on timeout we destroy the socket and reject (which
 * {@link runTreeScan} degrades to a skip). Short, since the broker answers a
 * local socket immediately when healthy.
 */
const FETCH_TIMEOUT_MS = 2000;

/**
 * Fetch the broker's known redaction-set values over the `CHAFF_SOCK` socket.
 * Sends one `redaction-set` request and resolves with the `patterns` (the real
 * secret values). Uses the broker's newline-delimited JSON wire protocol
 * (broker.ts): write one request line, read one response line. Rejects on a
 * connection error, a malformed response, or a timeout (a broker that connects
 * but never sends a newline-terminated line, which would otherwise hang the
 * scan forever).
 */
export function fetchRedactionValues(sockPath: string): Promise<string[]> {
  return new Promise<string[]>((resolve, reject) => {
    const conn = createConnection(sockPath);
    let buf = '';
    conn.setTimeout(FETCH_TIMEOUT_MS, () => {
      conn.destroy();
      reject(new Error('broker redaction-set fetch timed out'));
    });
    conn.on('error', reject);
    conn.on('connect', () => {
      conn.write(JSON.stringify({ op: 'redaction-set' }) + '\n');
    });
    conn.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl === -1) {
        return;
      }
      const line = buf.slice(0, nl);
      conn.destroy();
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      const res = parsed as { patterns?: unknown };
      if (Array.isArray(res.patterns) && res.patterns.every((p) => typeof p === 'string')) {
        resolve(res.patterns);
        return;
      }
      reject(new Error('broker redaction-set returned no patterns'));
    });
  });
}

/** Inputs to {@link runTreeScan}. */
export interface RunTreeScanOptions {
  /** The directory tree to scan. */
  cwd: string;
  /**
   * The broker socket path. When undefined/empty there is no broker to fetch
   * known values from, so the scan is reported as skipped rather than run.
   */
  sockPath: string | undefined;
}

/**
 * The outcome of the working-tree scan: either it ran (with whatever findings)
 * or it was skipped because no broker was reachable (`CHAFF_SOCK` unset).
 */
export type TreeScanResult =
  | { kind: 'ran'; findings: TreeFinding[] }
  | { kind: 'skipped'; reason: string };

/**
 * Run the working-tree scan end-to-end: fetch the broker's known values via
 * `CHAFF_SOCK`, then grep `cwd` for them. When `CHAFF_SOCK` is unset, returns a
 * `skipped` result rather than crashing (the common standalone `chaff scan`
 * case, where no session broker exists). A set-but-unreachable socket (a stale
 * socket from a crashed prior session, or a broker that never answers) also
 * degrades to `skipped` rather than rejecting — a detective scan must never fail
 * the scan. Detective only — it returns findings; it never throws to block the
 * scan.
 */
export async function runTreeScan(options: RunTreeScanOptions): Promise<TreeScanResult> {
  if (options.sockPath === undefined || options.sockPath.length === 0) {
    return {
      kind: 'skipped',
      reason: 'CHAFF_SOCK is not set — no broker to read known secret values from',
    };
  }
  let values: string[];
  try {
    values = await fetchRedactionValues(options.sockPath);
  } catch {
    return {
      kind: 'skipped',
      reason: 'broker unreachable — could not read known secret values',
    };
  }
  return { kind: 'ran', findings: scanTree({ values, root: options.cwd }) };
}

/**
 * Render a {@link TreeScanResult} as a working-tree-scan report section. A
 * `skipped` result renders a one-line skip notice; a `ran` result renders the
 * detective findings ({@link formatTreeFindings}) or a clean-tree line when there
 * are none. Never echoes a secret value.
 */
export function formatTreeScanResult(result: TreeScanResult): string {
  if (result.kind === 'skipped') {
    return `working-tree scan: skipped (${result.reason})\n`;
  }
  if (result.findings.length === 0) {
    return 'working-tree scan: no known secret values found on disk\n';
  }
  return formatTreeFindings(result.findings);
}
