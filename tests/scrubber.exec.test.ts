import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Buffer } from 'node:buffer';
import { formatHandle } from '../src/handles.js';
import { startBroker, type Broker } from '../src/broker.js';
import { runExec } from '../src/exec.js';
import { createScrubber, redactionEntriesFromSecrets } from '../src/scrubber.js';
import { buildRedactionSet } from '../src/redaction.js';
import { encodedVariants } from '../src/encodings.js';

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const BIN = join(SRC_DIR, '..', 'dist', 'bin', 'chaff.js');

const pexecFile = promisify(execFile);

function b64(command: string): string {
  return Buffer.from(command, 'utf8').toString('base64');
}

/** Collect all chunks a scrubber emits for a single buffer, as a UTF-8 string. */
function scrubAll(scrubber: ReturnType<typeof createScrubber>, input: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const out: Buffer[] = [];
    scrubber.on('data', (c: Buffer) => out.push(Buffer.from(c)));
    scrubber.on('end', () => resolve(Buffer.concat(out).toString('utf8')));
    scrubber.on('error', reject);
    scrubber.end(input);
  });
}

let tmp: string;
let logPath: string;
let savedXdg: string | undefined;
let broker: Broker | undefined;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-scrub-'));
  logPath = join(tmp, 'audit.jsonl');
  savedXdg = process.env.XDG_RUNTIME_DIR;
  process.env.XDG_RUNTIME_DIR = tmp;
});

afterEach(() => {
  if (broker !== undefined) {
    broker.close();
    broker = undefined;
  }
  if (savedXdg === undefined) {
    delete process.env.XDG_RUNTIME_DIR;
  } else {
    process.env.XDG_RUNTIME_DIR = savedXdg;
  }
  rmSync(tmp, { recursive: true, force: true });
});

describe('ac-1 integration: exec pipes stdout AND stderr through scrubbers', () => {
  it('exec runs the child with stdout AND stderr piped (not inherit) and routes each through a scrubber Transform: a child that writes a secret to stdout and a (different) secret to stderr has both redacted independently', async () => {
    const stdoutSecret = 'stdout-secret-value-aaaaaa';
    const stderrSecret = 'stderr-secret-value-bbbbbb';
    const stdoutHandle = formatHandle('OUT_SECRET');
    const stderrHandle = formatHandle('ERR_SECRET');
    broker = await startBroker({
      secrets: [
        { name: 'OUT_SECRET', value: stdoutSecret, handle: stdoutHandle },
        { name: 'ERR_SECRET', value: stderrSecret, handle: stderrHandle },
      ],
      auditLogPath: logPath,
    });

    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    const code = await runExec({
      args: ['--b64', b64(`printf '%s' "$OUT_SECRET"; printf '%s' "$ERR_SECRET" 1>&2`)],
      env: { OUT_SECRET: stdoutHandle, ERR_SECRET: stderrHandle },
      sockPath: broker.sockPath,
      stdout: {
        write: (c: string | Buffer) => {
          outChunks.push(Buffer.from(c));
          return true;
        },
      },
      stderr: {
        write: (c: string | Buffer) => {
          errChunks.push(Buffer.from(c));
          return true;
        },
      },
    });
    expect(code).toBe(0);
    const outText = Buffer.concat(outChunks).toString('utf8');
    const errText = Buffer.concat(errChunks).toString('utf8');
    expect(outText).toContain('[redacted:OUT_SECRET]');
    expect(outText).not.toContain(stdoutSecret);
    expect(errText).toContain('[redacted:ERR_SECRET]');
    expect(errText).not.toContain(stderrSecret);
  });
});

describe('ac-6 integration with the gate (buildRedactionSet)', () => {
  it('a short/common secret value (e.g. ‘test’, ‘prod’) that the gate excludes contributes no pattern, so innocent output containing that string (e.g. `npm test`) passes through unredacted', () => {
    const secrets = [{ name: 'ENV', value: 'prod' }];
    const set = buildRedactionSet({ secrets });
    // The gate excludes it.
    expect(set.patterns).toHaveLength(0);
    expect(set.skipped.map((s) => s.name)).toContain('ENV');
    // The scrubber, built from the gated secrets, has no entry for it.
    const entries = redactionEntriesFromSecrets(secrets);
    const scrubber = createScrubber({ entries });
    return scrubAll(scrubber, 'npm test && cd prod/').then((output) => {
      expect(output).toBe('npm test && cd prod/');
    });
  });

  it('a gate-eligible long/high-entropy secret IS in the pattern set and its raw and base64 forms are both redacted from output end-to-end', async () => {
    const value = 'Hg83kfPq19zXmTb47nLs';
    const secrets = [{ name: 'API_KEY', value }];
    const set = buildRedactionSet({ secrets });
    expect(set.patterns.length).toBeGreaterThan(0);
    expect(set.skipped).toHaveLength(0);

    const b64Form = Buffer.from(value, 'utf8').toString('base64');
    const entries = redactionEntriesFromSecrets(secrets);
    const scrubber = createScrubber({ entries });
    const output = await scrubAll(scrubber, `raw=${value} b64=${b64Form}`);
    expect(output).toBe('raw=[redacted:API_KEY] b64=[redacted:API_KEY]');
    expect(output).not.toContain(value);
    expect(output).not.toContain(b64Form);
  });

  it('redactionEntriesFromSecrets honours the gate: a short secret contributes no entry while a long one contributes its variants', () => {
    const entries = redactionEntriesFromSecrets([
      { name: 'SHORT', value: 'test' },
      { name: 'LONG', value: 'Hg83kfPq19zXmTb47nLs' },
    ]);
    const names = entries.map((e) => e.name);
    expect(names).not.toContain('SHORT');
    expect(names).toContain('LONG');
    const longEntry = entries.find((e) => e.name === 'LONG')!;
    expect(longEntry.patterns).toEqual(
      expect.arrayContaining(encodedVariants('Hg83kfPq19zXmTb47nLs')),
    );
  });
});

describe('ac-5 e2e via the built chaff binary', () => {
  it('`chaff exec --b64 <printenv SECRET>` with a handle in SECRET and the secret in the gated set prints [redacted:SECRET] on stdout, and the real value appears nowhere in the captured stdout', async () => {
    const real = 'e2e-stdout-secret-Hg83kfPq19';
    const handle = formatHandle('SECRET');
    broker = await startBroker({
      secrets: [{ name: 'SECRET', value: real, handle }],
      auditLogPath: logPath,
    });
    const { stdout } = await pexecFile(
      process.execPath,
      [BIN, 'exec', '--b64', b64('printenv SECRET')],
      { encoding: 'utf8', env: { ...process.env, SECRET: handle, CHAFF_SOCK: broker.sockPath } },
    );
    expect(stdout).toContain('[redacted:SECRET]');
    expect(stdout).not.toContain(real);
  });

  it('a child writing the secret to stderr has it redacted in chaff’s captured stderr too (both streams are wired through the scrubber)', async () => {
    const real = 'e2e-stderr-secret-Hg83kfPq19';
    const handle = formatHandle('SECRET');
    broker = await startBroker({
      secrets: [{ name: 'SECRET', value: real, handle }],
      auditLogPath: logPath,
    });
    const { stderr } = await pexecFile(
      process.execPath,
      [BIN, 'exec', '--b64', b64('printenv SECRET 1>&2')],
      { encoding: 'utf8', env: { ...process.env, SECRET: handle, CHAFF_SOCK: broker.sockPath } },
    );
    expect(stderr).toContain('[redacted:SECRET]');
    expect(stderr).not.toContain(real);
  });
});
