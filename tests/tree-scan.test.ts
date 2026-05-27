/**
 * DAR-1106 — `chaff scan` working-tree secret scan (decision #4).
 *
 * A detective control: grep the cwd tree for the broker's known redaction-set
 * values and warn by file LOCATION only (never echoing the matched value). The
 * pure tree walk ({@link scanTree}) is split from the broker I/O
 * ({@link fetchRedactionValues}) so the matching logic is unit-testable without
 * a running broker.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  scanTree,
  fetchRedactionValues,
  formatTreeFindings,
  runTreeScan,
  type TreeFinding,
} from '../src/tree-scan.js';
import { startBroker, type Broker } from '../src/broker.js';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-tree-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

/** Write a file with `contents` at `relPath` under the temp tree, mkdir -p'ing. */
function plant(relPath: string, contents: string): string {
  const full = join(tmp, relPath);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, contents, 'utf8');
  return full;
}

describe('scanTree — finds a planted redaction value by file location (ac-2)', () => {
  it('the working-tree scan, given a set of known redaction values and a directory tree containing a file whose contents include one of those values, returns a finding identifying the file path that contains the planted value', () => {
    const secret = 'sk-PLANTED-SECRET-abcdef0123456789';
    const planted = plant('sub/leaked.txt', `config:\nkey=${secret}\n`);
    const findings = scanTree({ values: [secret], root: tmp });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.map((f) => f.path)).toContain(planted);
  });

  it('the working-tree scan returns no finding when no file under the tree contains any known redaction value (a clean tree warns about nothing)', () => {
    plant('a.txt', 'nothing to see here\n');
    plant('nested/b.ts', 'export const x = 1;\n');
    const findings = scanTree({ values: ['sk-PLANTED-SECRET-abcdef0123456789'], root: tmp });
    expect(findings).toEqual([]);
  });

  it('the working-tree scan reports findings by file location only and never echoes the matched secret value into its output/warning text', () => {
    const secret = 'sk-PLANTED-SECRET-abcdef0123456789';
    plant('sub/leaked.txt', `key=${secret}\n`);
    const findings = scanTree({ values: [secret], root: tmp });
    // The finding object carries no value field, and the rendered warning text
    // never contains the secret.
    for (const finding of findings) {
      expect(JSON.stringify(finding)).not.toContain(secret);
    }
    const rendered = formatTreeFindings(findings);
    expect(rendered).not.toContain(secret);
    // It still names the file location.
    expect(rendered).toContain('leaked.txt');
  });

  it('an empty values set finds nothing (no broker secrets means nothing to detect)', () => {
    plant('a.txt', 'anything\n');
    expect(scanTree({ values: [], root: tmp })).toEqual([]);
  });
});

describe('fetchRedactionValues — obtains known values from the broker (ac-2 integration)', () => {
  let broker: Broker | undefined;

  afterEach(() => {
    broker?.close();
    broker = undefined;
  });

  it("the working-tree scan obtains its known values from the broker redaction-set op via CHAFF_SOCK (given a running broker holding a secret, scanning a tree containing that secret's value flags the file)", async () => {
    const secret = 'sk-BROKER-HELD-SECRET-0123456789ab';
    const auditLogPath = join(tmp, 'audit.jsonl');
    broker = await startBroker({
      secrets: [{ name: 'API_KEY', value: secret, handle: 'chaff:1:API_KEY:0123456789ab' }],
      auditLogPath,
    });
    const planted = plant('config/app.env', `API_KEY=${secret}\n`);

    const values = await fetchRedactionValues(broker.sockPath);
    expect(values).toContain(secret);

    const findings = scanTree({ values, root: tmp });
    expect(findings.map((f) => f.path)).toContain(planted);
    // A redaction-set fetch is not audited (only resolve is), so the audit log
    // need not even exist; if it does, it must never contain the secret value.
    if (existsSync(auditLogPath)) {
      expect(readFileSync(auditLogPath, 'utf8')).not.toContain(secret);
    }
  });
});

describe('runTreeScan — degrades, never fails the scan (ac-2, f-1)', () => {
  it('degrades to a skipped result (not a rejection) when CHAFF_SOCK is set but points at a dead/non-listening socket — a detective scan must not fail the scan', async () => {
    // A stale socket path from a crashed prior session: set, but nothing is
    // listening, so fetchRedactionValues rejects. runTreeScan must swallow that
    // and report a skip rather than propagating the rejection (which would set
    // exit 1 in the bin and fail the whole `chaff scan`).
    const deadSock = join(tmp, 'nonexistent.sock');
    const result = await runTreeScan({ cwd: tmp, sockPath: deadSock });
    expect(result.kind).toBe('skipped');
    if (result.kind === 'skipped') {
      expect(result.reason.toLowerCase()).toContain('broker unreachable');
    }
  });
});

describe('formatTreeFindings — detective rendering (ac-2)', () => {
  it('renders a warning header plus each file location, and an empty finding list renders no warning section', () => {
    expect(formatTreeFindings([])).toBe('');
    const findings: TreeFinding[] = [{ path: '/repo/sub/leaked.txt' }];
    const rendered = formatTreeFindings(findings);
    expect(rendered).toContain('/repo/sub/leaked.txt');
    // Detective, not preventive: the wording warns, it does not say denied/blocked.
    expect(rendered.toLowerCase()).toMatch(/warn/);
  });
});
