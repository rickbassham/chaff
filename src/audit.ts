/**
 * Broker-side audit trail of secret resolutions.
 *
 * The broker appends one line per operation to an append-only JSONL log. Each
 * entry is exactly `{ts, op, secretName}` — **no peer pid/argv** (PLAN.md
 * decision #1: Node cannot read peer credentials without a native addon, and
 * the accidental-leakage threat model does not need them) and **never the
 * secret value** (only its name), so logging on every `resolve` cannot leak a
 * resolved value.
 *
 * The writer is built to be called on every broker `resolve`:
 *   - cheap: it appends and never reads the existing log back in, so its cost
 *     does not scale with log size;
 *   - safe: an I/O failure is swallowed, never thrown into the caller, so a
 *     broken audit log can never break a `resolve`.
 *
 * `chaff audit` reads the log via {@link formatAuditLog} and pretty-prints it.
 *
 * This module is log writing + printing only. The broker wires its `resolve`
 * into the writer (DAR-1097); CLI argv dispatch routes `chaff audit` here
 * (launcher/bin wiring). Neither is this module's concern.
 */

import { appendFileSync, readFileSync } from 'node:fs';

/** A single audit log entry. Exactly these three fields, nothing else. */
export interface AuditEntry {
  /** ISO-8601 timestamp of when the entry was written. */
  ts: string;
  /** The broker operation that produced the entry (e.g. `resolve`, `list`). */
  op: string;
  /** The NAME of the secret involved — never its value. */
  secretName: string;
}

/** The fields a caller supplies; the writer stamps `ts` itself. */
export interface AuditRecord {
  op: string;
  secretName: string;
}

/**
 * Append one `{ts, op, secretName}` entry to the JSONL log at `logPath`.
 *
 * Stamps `ts` with the current time. Only `op` and `secretName` are read from
 * `record`, so no extra fields (and crucially no secret value) can ever reach
 * the log. Appends a single newline-terminated line without reading the
 * existing log, so the cost is independent of log size.
 *
 * Never throws: any I/O error (e.g. an un-writable or missing parent
 * directory) is swallowed so a failing audit log can never break a broker
 * `resolve`.
 */
export function writeAuditEntry(logPath: string, record: AuditRecord): void {
  const entry: AuditEntry = {
    ts: new Date().toISOString(),
    op: record.op,
    secretName: record.secretName,
  };
  try {
    appendFileSync(logPath, JSON.stringify(entry) + '\n');
  } catch {
    // Audit is best-effort: a write failure must never propagate into the
    // caller and break the operation being audited.
  }
}

/**
 * Read and parse every entry in the JSONL log at `logPath`, in write order.
 *
 * Returns an empty array for a missing or empty log. Blank lines are skipped;
 * a malformed (non-parseable) line is skipped rather than throwing, so a
 * partially-corrupt log still yields its readable entries.
 */
export function readAuditLog(logPath: string): AuditEntry[] {
  let raw: string;
  try {
    raw = readFileSync(logPath, 'utf8');
  } catch {
    return [];
  }

  const entries: AuditEntry[] = [];
  for (const line of raw.split('\n')) {
    if (line.length === 0) {
      continue;
    }
    try {
      const parsed = JSON.parse(line) as Partial<AuditEntry>;
      if (
        typeof parsed.ts === 'string' &&
        typeof parsed.op === 'string' &&
        typeof parsed.secretName === 'string'
      ) {
        entries.push({ ts: parsed.ts, op: parsed.op, secretName: parsed.secretName });
      }
    } catch {
      // Skip unparseable lines; a corrupt entry shouldn't hide the rest.
    }
  }
  return entries;
}

/** Format a single entry as one stable, human-readable line. */
export function formatAuditEntry(entry: AuditEntry): string {
  return `${entry.ts}  ${entry.op}  ${entry.secretName}`;
}

/**
 * Read the JSONL log at `logPath` and return its pretty-printed form: one
 * {@link formatAuditEntry} line per entry, in order, newline-joined. Returns
 * an empty string for a missing or empty log (no entries, no throw).
 */
export function formatAuditLog(logPath: string): string {
  return readAuditLog(logPath).map(formatAuditEntry).join('\n');
}
