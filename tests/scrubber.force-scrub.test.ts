/**
 * DAR-1150 — `--force-scrub NAME` is honored on the `chaff exec` egress path.
 *
 * The exec egress scrubber rebuilds its pattern set locally via
 * {@link redactionEntriesFromSecrets}, which previously consumed only the
 * redaction-eligibility gate ({@link isRedactionEligible}) and so silently
 * ignored `--force-scrub`. These tests pin the wired behavior: a force-scrubbed
 * gate-failing value IS redacted to `[redacted:NAME]` on both exec streams,
 * carries the secret NAME through, keeps the per-variant min-length floor, and
 * still leaves a non-forced short secret's innocent output intact.
 *
 * The force-scrub name set reaches the separate `chaff exec` process through the
 * `CHAFF_FORCE_SCRUB` env var the launcher seeds into the harness env (the same
 * env channel as `CHAFF_SOCK`). Option (b) of AC-2: thread force-scrub into
 * exec's `redactionEntriesFromSecrets` path.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { Buffer } from 'node:buffer';
import { formatHandle } from '../src/handles.js';
import { startBroker, type Broker } from '../src/broker.js';
import { runExec } from '../src/exec.js';
import { redactionEntriesFromSecrets } from '../src/scrubber.js';
import { buildRedactionSet, gatedVariants } from '../src/redaction.js';

const SRC_DIR = dirname(fileURLToPath(import.meta.url));
const BIN = join(SRC_DIR, '..', 'dist', 'bin', 'chaff.js');

function b64(command: string): string {
  return Buffer.from(command, 'utf8').toString('base64');
}

/** Run a child via runExec capturing scrubbed stdout/stderr separately. */
async function execCapture(opts: {
  command: string;
  env: Record<string, string>;
  sockPath: string;
  forceScrub?: string[];
}): Promise<{ code: number; stdout: string; stderr: string }> {
  const outChunks: Buffer[] = [];
  const errChunks: Buffer[] = [];
  const code = await runExec({
    args: ['--b64', b64(opts.command)],
    env: opts.env,
    sockPath: opts.sockPath,
    forceScrub: opts.forceScrub,
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
  return {
    code,
    stdout: Buffer.concat(outChunks).toString('utf8'),
    stderr: Buffer.concat(errChunks).toString('utf8'),
  };
}

let tmp: string;
let logPath: string;
let savedXdg: string | undefined;
let broker: Broker | undefined;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-fscrub-'));
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

describe('ac-1: force-scrubbed gate-failing value is redacted on exec egress', () => {
  it('exec egress: a force-scrubbed short/low-entropy secret value printed by the child to stdout is replaced with [redacted:NAME] and the raw value appears nowhere in the scrubbed stdout', async () => {
    // `prod` fails the value-level gate (short + low entropy) but is long enough
    // here? No — pad to a value that clears the per-variant floor but fails the
    // value gate via low entropy, so the floor does not exclude it.
    const value = 'prodprodprod'; // 12 chars: clears length floor, low entropy -> gate-failing.
    const handle = formatHandle('DEPLOY_ENV');
    broker = await startBroker({
      secrets: [{ name: 'DEPLOY_ENV', value, handle }],
      auditLogPath: logPath,
    });
    const { code, stdout } = await execCapture({
      command: `printf '%s' "$DEPLOY_ENV"`,
      env: { DEPLOY_ENV: handle },
      sockPath: broker.sockPath,
      forceScrub: ['DEPLOY_ENV'],
    });
    expect(code).toBe(0);
    expect(stdout).toContain('[redacted:DEPLOY_ENV]');
    expect(stdout).not.toContain(value);
  });

  it('exec egress: the same force-scrubbed short/low-entropy secret printed by the child to stderr is replaced with [redacted:NAME] and the raw value appears nowhere in the scrubbed stderr (both streams honor force-scrub, not just stdout)', async () => {
    const value = 'prodprodprod';
    const handle = formatHandle('DEPLOY_ENV');
    broker = await startBroker({
      secrets: [{ name: 'DEPLOY_ENV', value, handle }],
      auditLogPath: logPath,
    });
    const { code, stderr } = await execCapture({
      command: `printf '%s' "$DEPLOY_ENV" 1>&2`,
      env: { DEPLOY_ENV: handle },
      sockPath: broker.sockPath,
      forceScrub: ['DEPLOY_ENV'],
    });
    expect(code).toBe(0);
    expect(stderr).toContain('[redacted:DEPLOY_ENV]');
    expect(stderr).not.toContain(value);
  });
});

describe('ac-2 (option b): force-scrub threaded into redactionEntriesFromSecrets', () => {
  it('the chosen mechanism carries the per-secret NAME to the exec scrubber so the emitted token is [redacted:NAME] (NAME, never the secret value) for a force-scrubbed secret — asserted as the exact [redacted:NAME] token, not a generic [redacted]', async () => {
    const value = 'prodprodprod';
    const handle = formatHandle('DEPLOY_ENV');
    broker = await startBroker({
      secrets: [{ name: 'DEPLOY_ENV', value, handle }],
      auditLogPath: logPath,
    });
    const { stdout } = await execCapture({
      command: `printf '%s' "$DEPLOY_ENV"`,
      env: { DEPLOY_ENV: handle },
      sockPath: broker.sockPath,
      forceScrub: ['DEPLOY_ENV'],
    });
    expect(stdout).toBe('[redacted:DEPLOY_ENV]');
    expect(stdout).not.toContain('[redacted]');
  });

  it('option (b): redactionEntriesFromSecrets given a force-scrub name set produces an entry for a gate-failing named secret and no entry for a gate-failing un-named secret', () => {
    const secrets = [
      { name: 'FORCED', value: 'prodprodprod' },
      { name: 'NOT_FORCED', value: 'prodprodprod' },
    ];
    const entries = redactionEntriesFromSecrets(secrets, ['FORCED']);
    const names = entries.map((e) => e.name);
    expect(names).toContain('FORCED');
    expect(names).not.toContain('NOT_FORCED');
  });
});

describe('ac-3: per-variant min-length floor still applies under force-scrub', () => {
  it('a force-scrubbed secret whose value clears the per-variant length floor but fails the value-level gate (low-entropy long value) IS redacted on exec egress', async () => {
    const value = 'aaaaaaaaaaaa'; // 12 chars: clears floor; ~0 entropy -> value gate fails.
    const handle = formatHandle('LOWENT');
    broker = await startBroker({
      secrets: [{ name: 'LOWENT', value, handle }],
      auditLogPath: logPath,
    });
    const { stdout } = await execCapture({
      command: `printf '%s' "$LOWENT"`,
      env: { LOWENT: handle },
      sockPath: broker.sockPath,
      forceScrub: ['LOWENT'],
    });
    expect(stdout).toContain('[redacted:LOWENT]');
    expect(stdout).not.toContain(value);
  });

  it('a force-scrubbed secret with a short value: variants below the per-variant min-length floor are NOT entered as patterns even under force-scrub, so innocent output containing such a short collision-prone string passes through unredacted on exec egress', async () => {
    const value = 'prod'; // below the per-variant length floor (DEFAULT_MIN_LENGTH = 8).
    const handle = formatHandle('ENV');
    broker = await startBroker({
      secrets: [{ name: 'ENV', value, handle }],
      auditLogPath: logPath,
    });
    const { stdout } = await execCapture({
      // The child prints an innocent string containing the short value.
      command: `printf 'npm test && cd %s/' "$ENV"`,
      env: { ENV: handle },
      sockPath: broker.sockPath,
      forceScrub: ['ENV'],
    });
    expect(stdout).toBe('npm test && cd prod/');
  });

  it('the exec force-scrub path derives variants through the shared gatedVariants helper, so the floor applies identically on the exec path and the launcher/broker path for the same value', () => {
    const value = 'prodprodprod';
    // Exec path: force-scrubbed entry's patterns.
    const entries = redactionEntriesFromSecrets([{ name: 'X', value }], ['X']);
    const execPatterns = entries.find((e) => e.name === 'X')!.patterns;
    // Launcher/broker path: buildRedactionSet with the same force-scrub.
    const set = buildRedactionSet({ secrets: [{ name: 'X', value }], forceScrub: ['X'] });
    // Both derive from the same gatedVariants source of truth.
    expect(execPatterns).toEqual(gatedVariants(value, {}));
    expect(set.patterns).toEqual(gatedVariants(value, {}));
    expect(execPatterns).toEqual(set.patterns);
  });
});

describe('ac-4: forced short secret redacted; non-forced short secret leaves output intact', () => {
  it('with NAME in force-scrub: a short/low-entropy secret value the gate would exclude IS redacted to [redacted:NAME] on exec egress', async () => {
    const value = 'prodprodprod';
    const handle = formatHandle('DEPLOY_ENV');
    broker = await startBroker({
      secrets: [{ name: 'DEPLOY_ENV', value, handle }],
      auditLogPath: logPath,
    });
    const { stdout } = await execCapture({
      command: `printf '%s' "$DEPLOY_ENV"`,
      env: { DEPLOY_ENV: handle },
      sockPath: broker.sockPath,
      forceScrub: ['DEPLOY_ENV'],
    });
    expect(stdout).toContain('[redacted:DEPLOY_ENV]');
  });

  it('without force-scrub (or for a different NAME not in the force-scrub set): a gate-failing short secret value contributes no pattern, so innocent output containing that string passes through the exec scrubber unredacted', async () => {
    const value = 'prodprodprod';
    const handle = formatHandle('DEPLOY_ENV');
    broker = await startBroker({
      secrets: [{ name: 'DEPLOY_ENV', value, handle }],
      auditLogPath: logPath,
    });
    // A different NAME is force-scrubbed, so DEPLOY_ENV stays gate-excluded.
    const { stdout } = await execCapture({
      command: `printf 'deploying to %s now' "$DEPLOY_ENV"`,
      env: { DEPLOY_ENV: handle },
      sockPath: broker.sockPath,
      forceScrub: ['SOMETHING_ELSE'],
    });
    expect(stdout).toBe('deploying to prodprodprod now');
    expect(stdout).not.toContain('[redacted');
  });
});

describe('ac-1 e2e: chaff run --force-scrub NAME -- <child runs chaff exec>', () => {
  it('via the built chaff binary: a child invoked through chaff exec --b64 that prints the gate-failing secret has it redacted to [redacted:NAME] in the captured output, with the real value absent', () => {
    if (!existsSync(BIN)) {
      throw new Error(`built binary missing at ${BIN}; run \`make build\` first`);
    }
    const real = 'prodprodprod'; // gate-failing (low entropy), clears the floor.
    // DEPLOY_SECRET matches the `*_SECRET` name glob, so `chaff run` handles it
    // (gives the harness a handle) rather than dropping it under default-deny.
    // The harness is a node script that runs `chaff exec --b64 <printenv DEPLOY_SECRET>`.
    // Under `chaff run` the harness env carries the handle for DEPLOY_SECRET plus
    // CHAFF_SOCK and (because of --force-scrub) CHAFF_FORCE_SCRUB; chaff exec
    // resolves the handle and the egress scrubber redacts the forced value.
    const harness = join(tmp, 'harness.mjs');
    const innerBlob = b64('printenv DEPLOY_SECRET');
    writeFileSync(
      harness,
      `import { execFileSync } from 'node:child_process';\n` +
        `const out = execFileSync(process.execPath, [${JSON.stringify(BIN)}, 'exec', '--b64', ${JSON.stringify(innerBlob)}], { encoding: 'utf8' });\n` +
        `process.stdout.write(out);\n`,
    );
    let stdout: string;
    try {
      stdout = execFileSync(
        process.execPath,
        [BIN, 'run', '--force-scrub', 'DEPLOY_SECRET', '--', process.execPath, harness],
        {
          encoding: 'utf8',
          env: { ...process.env, DEPLOY_SECRET: real, XDG_RUNTIME_DIR: tmp },
        },
      );
    } catch (err) {
      const e = err as { stdout?: string };
      stdout = e.stdout ?? '';
    }
    expect(stdout).toContain('[redacted:DEPLOY_SECRET]');
    expect(stdout).not.toContain(real);
  });
});
