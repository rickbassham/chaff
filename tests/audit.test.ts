import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  writeAuditEntry,
  readAuditLog,
  formatAuditEntry,
  formatAuditLog,
  type AuditEntry,
} from '../src/audit.js';

let dir: string;
let logPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'chaff-audit-'));
  logPath = join(dir, 'audit.jsonl');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Parse a JSONL log file into an array of parsed objects (one per line). */
function readLines(path: string): unknown[] {
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line));
}

describe('writeAuditEntry — JSONL writer (ac-1)', () => {
  it('writing one entry appends a single line of valid JSON whose parsed object has exactly the keys ts, op, secretName (no pid, argv, or other keys)', () => {
    writeAuditEntry(logPath, { op: 'resolve', secretName: 'OPENAI_API_KEY' });

    const lines = readLines(logPath);
    expect(lines).toHaveLength(1);
    const entry = lines[0] as Record<string, unknown>;
    expect(Object.keys(entry).sort()).toEqual(['op', 'secretName', 'ts']);
    expect(entry).not.toHaveProperty('pid');
    expect(entry).not.toHaveProperty('argv');
  });

  it('writing N entries to the same log produces N newline-delimited lines, each independently JSON.parse-able, in write order', () => {
    writeAuditEntry(logPath, { op: 'resolve', secretName: 'A_KEY' });
    writeAuditEntry(logPath, { op: 'list', secretName: 'B_TOKEN' });
    writeAuditEntry(logPath, { op: 'resolve', secretName: 'C_SECRET' });

    const lines = readLines(logPath);
    expect(lines).toHaveLength(3);
    expect((lines[0] as AuditEntry).secretName).toBe('A_KEY');
    expect((lines[1] as AuditEntry).secretName).toBe('B_TOKEN');
    expect((lines[2] as AuditEntry).secretName).toBe('C_SECRET');
  });

  it('writing to a log that already has content appends after the existing lines and does not truncate or overwrite the prior entries', () => {
    const seeded = JSON.stringify({
      ts: '2020-01-01T00:00:00.000Z',
      op: 'resolve',
      secretName: 'PRIOR',
    });
    writeFileSync(logPath, seeded + '\n');

    writeAuditEntry(logPath, { op: 'resolve', secretName: 'NEW' });

    const lines = readLines(logPath);
    expect(lines).toHaveLength(2);
    expect((lines[0] as AuditEntry).secretName).toBe('PRIOR');
    expect((lines[1] as AuditEntry).secretName).toBe('NEW');
  });

  it('the persisted ts field round-trips to the time the entry was written, and op/secretName persist the exact strings passed in', () => {
    const before = Date.now();
    writeAuditEntry(logPath, { op: 'resolve', secretName: 'TIME_KEY' });
    const after = Date.now();

    const entry = readLines(logPath)[0] as AuditEntry;
    const parsedTs = new Date(entry.ts).getTime();
    expect(Number.isNaN(parsedTs)).toBe(false);
    expect(parsedTs).toBeGreaterThanOrEqual(before);
    expect(parsedTs).toBeLessThanOrEqual(after);
    expect(entry.op).toBe('resolve');
    expect(entry.secretName).toBe('TIME_KEY');
  });
});

describe('formatAuditEntry — single-line formatter (ac-2)', () => {
  it('formats one entry into a single line containing its ts, op, and secretName', () => {
    const entry: AuditEntry = {
      ts: '2026-05-23T10:00:00.000Z',
      op: 'resolve',
      secretName: 'GAMMA_KEY',
    };
    const line = formatAuditEntry(entry);
    expect(line).not.toContain('\n');
    expect(line).toContain(entry.ts);
    expect(line).toContain(entry.op);
    expect(line).toContain(entry.secretName);
  });
});

describe('formatAuditLog — reader/printer (ac-2)', () => {
  it("the printer given a log file path reads every JSONL entry and emits one formatted line per entry containing that entry's ts, op, and secretName", () => {
    const entries: AuditEntry[] = [
      { ts: '2026-05-23T10:00:00.000Z', op: 'resolve', secretName: 'ALPHA_KEY' },
      { ts: '2026-05-23T10:00:01.000Z', op: 'list', secretName: 'BETA_TOKEN' },
    ];
    writeFileSync(logPath, entries.map((e) => JSON.stringify(e)).join('\n') + '\n');

    const output = formatAuditLog(logPath);
    const lines = output.split('\n').filter((l) => l.length > 0);
    expect(lines).toHaveLength(2);
    for (const entry of entries) {
      const line = lines.find((l) => l.includes(entry.secretName));
      expect(line).toBeDefined();
      expect(line).toContain(entry.ts);
      expect(line).toContain(entry.op);
      expect(line).toContain(entry.secretName);
    }
  });

  it('write→read round-trip through the public API: entries written by the writer are read back by the printer and the formatted output reflects each written entry in order', () => {
    writeAuditEntry(logPath, { op: 'resolve', secretName: 'FIRST_KEY' });
    writeAuditEntry(logPath, { op: 'resolve', secretName: 'SECOND_KEY' });

    const output = formatAuditLog(logPath);
    const lines = output.split('\n').filter((l) => l.length > 0);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('FIRST_KEY');
    expect(lines[1]).toContain('SECOND_KEY');
    expect(lines[0]!.indexOf('FIRST_KEY')).toBeGreaterThanOrEqual(0);
  });

  it('the printer on an empty or non-existent log produces no entry lines and does not throw', () => {
    const missingPath = join(dir, 'does-not-exist.jsonl');
    expect(() => formatAuditLog(missingPath)).not.toThrow();
    expect(
      formatAuditLog(missingPath)
        .split('\n')
        .filter((l) => l.includes(':')),
    ).toEqual([]);

    writeFileSync(logPath, '');
    expect(() => formatAuditLog(logPath)).not.toThrow();
  });
});

describe('writer is cheap and safe (ac-3)', () => {
  it('the writer performs no full-file read before appending — appending to a pre-seeded large log does not read it back in', () => {
    // Pre-seed a large log. If the writer read the whole file, this would be
    // observable as cost; we assert correctness of an append without the
    // writer needing to parse the existing content.
    const bigLine = JSON.stringify({
      ts: '2020-01-01T00:00:00.000Z',
      op: 'resolve',
      secretName: 'X'.repeat(64),
    });
    const seeded = Array.from({ length: 10000 }, () => bigLine).join('\n') + '\n';
    writeFileSync(logPath, seeded);

    writeAuditEntry(logPath, { op: 'resolve', secretName: 'APPENDED' });

    const lines = readLines(logPath);
    expect(lines).toHaveLength(10001);
    expect((lines[10000] as AuditEntry).secretName).toBe('APPENDED');
  });

  it('a write that hits an I/O failure (un-writable/missing parent directory) does not throw out of the writer', () => {
    const unwritable = join(dir, 'no-such-subdir', 'audit.jsonl');
    expect(() => writeAuditEntry(unwritable, { op: 'resolve', secretName: 'SAFE' })).not.toThrow();
  });

  it('the writer never persists the secret VALUE — only secretName — even when a resolve-shaped payload smuggles the value alongside it', () => {
    const secretValue = 'sk-super-secret-value-do-not-leak-1234567890';
    // Simulate a caller that hands the writer a resolve payload carrying the
    // resolved value as an extra field. The writer reads only op + secretName,
    // so the value must never reach the log. The cast forces the excess field
    // past TypeScript precisely to prove the runtime contract drops it.
    const payload = { op: 'resolve', secretName: 'LEAK_KEY', value: secretValue };
    writeAuditEntry(logPath, payload as unknown as { op: string; secretName: string });

    const raw = readFileSync(logPath, 'utf8');
    expect(raw).not.toContain(secretValue);
    expect(raw).not.toContain('value');
    const entry = readLines(logPath)[0] as AuditEntry;
    expect(entry.secretName).toBe('LEAK_KEY');
    expect(Object.keys(entry).sort()).toEqual(['op', 'secretName', 'ts']);
  });
});

describe('unit tests: round-trip + sample log (ac-4)', () => {
  it('write→read round-trip: a sequence written via the writer is read back via the reader and deep-equals the written entries (modulo ts)', () => {
    const inputs = [
      { op: 'resolve', secretName: 'RT_ONE' },
      { op: 'list', secretName: 'RT_TWO' },
      { op: 'resolve', secretName: 'RT_THREE' },
    ];
    for (const input of inputs) {
      writeAuditEntry(logPath, input);
    }

    const readBack = readAuditLog(logPath);
    expect(readBack).toHaveLength(3);
    expect(readBack.map((e) => ({ op: e.op, secretName: e.secretName }))).toEqual(inputs);
    for (const entry of readBack) {
      expect(Object.keys(entry).sort()).toEqual(['op', 'secretName', 'ts']);
      expect(Number.isNaN(new Date(entry.ts).getTime())).toBe(false);
    }
  });

  it("printer formats a sample log: given a fixed sample JSONL fixture, the output contains each entry's ts, op, and secretName in a stable human-readable form", () => {
    const sample: AuditEntry[] = [
      { ts: '2026-05-23T12:00:00.000Z', op: 'resolve', secretName: 'SAMPLE_API_KEY' },
      { ts: '2026-05-23T12:00:05.500Z', op: 'list', secretName: 'SAMPLE_DB_URL' },
      { ts: '2026-05-23T12:01:00.000Z', op: 'resolve', secretName: 'SAMPLE_TOKEN' },
    ];
    writeFileSync(logPath, sample.map((e) => JSON.stringify(e)).join('\n') + '\n');

    const output = formatAuditLog(logPath);
    for (const entry of sample) {
      expect(output).toContain(entry.ts);
      expect(output).toContain(entry.op);
      expect(output).toContain(entry.secretName);
    }
    // Stable: formatting the same log twice yields identical output.
    expect(formatAuditLog(logPath)).toBe(output);
  });
});
