import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { formatHandle, isHandle } from '../src/handles.js';
import { startBroker, type Broker } from '../src/broker.js';
import {
  INNER_SHELL,
  decodeCommand,
  resolveChildEnv,
  resolveViaBroker,
  runExec,
} from '../src/exec.js';

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const BIN = join(SRC_DIR, '..', 'dist', 'bin', 'chaff.js');

/**
 * Run the built `chaff` binary asynchronously. The e2e broker runs in THIS
 * (the test) process, so the call must not block this event loop — a synchronous
 * `execFileSync` would freeze the broker and deadlock chaff's handle-resolve
 * request. The async form keeps the broker responsive while chaff runs.
 */
const pexecFile = promisify(execFile);

/** base64-encode a command string the way the hook (DAR-1104) will. */
function b64(command: string): string {
  return Buffer.from(command, 'utf8').toString('base64');
}

let tmp: string;
let logPath: string;
let savedXdg: string | undefined;
let broker: Broker | undefined;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-exec-'));
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

/**
 * Start a broker holding one secret named `name` with `realValue`, returning the
 * handle placed "in the env". Keeps the broker reference for afterEach teardown.
 */
async function brokerWithSecret(name: string, realValue: string): Promise<string> {
  const handle = formatHandle(name);
  broker = await startBroker({
    secrets: [{ name, value: realValue, handle }],
    auditLogPath: logPath,
  });
  return handle;
}

describe('ac-1: decode the blob, connect via CHAFF_SOCK, resolve handles into the child env, run under the inner shell', () => {
  it('given a base64 blob of a command, exec base64-decodes it and runs the decoded command string', async () => {
    // A non-trivial command round-trips to the exact original text on decode.
    const original = 'printenv MARKER && echo "done | with: metachars"';
    expect(decodeCommand(['--b64', b64(original)])).toBe(original);

    // And the decoded command actually executes: a decoded `printenv MARKER`
    // prints MARKER's value via exec's spawn.
    const handle = await brokerWithSecret('UNUSED', 'unused');
    const outFile = join(tmp, 'marker.txt');
    const code = await runExec({
      args: ['--b64', b64('printenv MARKER > ' + JSON.stringify(outFile))],
      env: { MARKER: 'marker-value', PLACEHOLDER: handle },
      sockPath: broker!.sockPath,
      stdio: 'ignore',
    });
    expect(code).toBe(0);
    expect(readFileSync(outFile, 'utf8').trim()).toBe('marker-value');
  });

  it('exec connects to the broker at process.env.CHAFF_SOCK and uses it for resolution; fails loudly when CHAFF_SOCK is unset', async () => {
    const real = 'sk-resolve-via-sock';
    const handle = await brokerWithSecret('SECRET', real);

    // resolveViaBroker against the started broker returns the real value.
    expect(await resolveViaBroker(broker!.sockPath, handle)).toBe(real);

    // With sockPath/CHAFF_SOCK missing, exec rejects rather than silently
    // passing the handle through.
    const savedSock = process.env.CHAFF_SOCK;
    delete process.env.CHAFF_SOCK;
    try {
      await expect(
        runExec({ args: ['--b64', b64('true')], env: { SECRET: handle } }),
      ).rejects.toThrow(/CHAFF_SOCK/);
    } finally {
      if (savedSock !== undefined) {
        process.env.CHAFF_SOCK = savedSock;
      }
    }
  });

  it('every isHandle() env var is replaced in the CHILD env by the broker resolve value; a non-handle var is passed through unchanged', async () => {
    const real = 'real-secret-abc';
    const handle = await brokerWithSecret('SECRET', real);
    const childEnv = await resolveChildEnv({ SECRET: handle, PLAIN: 'plain-value' }, (h) =>
      resolveViaBroker(broker!.sockPath, h),
    );
    expect(childEnv.SECRET).toBe(real);
    expect(childEnv.PLAIN).toBe('plain-value');
  });

  it('a child process reading process.env.SECRET prints the real secret value, not the handle', async () => {
    const real = 'sk-child-reads-env';
    const handle = await brokerWithSecret('SECRET', real);
    const outFile = join(tmp, 'child-env.txt');
    const code = await runExec({
      args: [
        '--b64',
        b64(
          `${JSON.stringify(process.execPath)} -e 'require("fs").writeFileSync(${JSON.stringify(
            outFile,
          )}, process.env.SECRET)'`,
        ),
      ],
      env: { SECRET: handle },
      sockPath: broker!.sockPath,
      stdio: 'ignore',
    });
    expect(code).toBe(0);
    const printed = readFileSync(outFile, 'utf8');
    expect(printed).toBe(real);
    expect(isHandle(printed)).toBe(false);
  });

  it('the decoded command is run under an inner shell with -c: a pipe, quote, and redirect are interpreted by the inner shell, not by exec argv parsing', async () => {
    const handle = await brokerWithSecret('UNUSED', 'unused');
    const outFile = join(tmp, 'metachars.txt');
    // Quotes + pipe + redirect all in one decoded command.
    const code = await runExec({
      args: ['--b64', b64(`echo "a b c" | tr ' ' '_' > ${JSON.stringify(outFile)}`)],
      env: { PLACEHOLDER: handle },
      sockPath: broker!.sockPath,
      stdio: 'ignore',
    });
    expect(code).toBe(0);
    expect(readFileSync(outFile, 'utf8').trim()).toBe('a_b_c');
  });

  it('e2e via the built chaff binary: `chaff exec --b64 <printenv SECRET>` with a handle in SECRET prints the real value', async () => {
    const real = 'sk-e2e-printenv-secret';
    const handle = await brokerWithSecret('SECRET', real);
    const { stdout } = await pexecFile(
      process.execPath,
      [BIN, 'exec', '--b64', b64('printenv SECRET')],
      { encoding: 'utf8', env: { ...process.env, SECRET: handle, CHAFF_SOCK: broker!.sockPath } },
    );
    expect(stdout.trim()).toBe(real);
  });
});

describe('ac-2: base64 wrapping is load-bearing — $VAR expansion and pipe/quote/redirect parsing happen in the inner shell with real values', () => {
  it('a `<tool> --key $SECRET` decoded command passes the RESOLVED real value to the tool as the --key argument', async () => {
    const real = 'sk-tool-flag-value';
    const handle = await brokerWithSecret('SECRET', real);
    // A dummy tool that records its argv.
    const recordFile = join(tmp, 'argv.json');
    const tool = join(tmp, 'tool.mjs');
    writeFileSync(
      tool,
      `import { writeFileSync } from 'node:fs';
       writeFileSync(${JSON.stringify(recordFile)}, JSON.stringify(process.argv.slice(2)));
      `,
    );
    const code = await runExec({
      args: [
        '--b64',
        b64(`${JSON.stringify(process.execPath)} ${JSON.stringify(tool)} --key $SECRET`),
      ],
      env: { SECRET: handle },
      sockPath: broker!.sockPath,
      stdio: 'ignore',
    });
    expect(code).toBe(0);
    const argv = JSON.parse(readFileSync(recordFile, 'utf8')) as string[];
    expect(argv).toEqual(['--key', real]);
    expect(argv).not.toContain(handle);
    expect(argv).not.toContain('$SECRET');
  });

  it('`echo $SECRET` expands inside the inner shell against the resolved child env, not in exec before spawn', async () => {
    const real = 'sk-var-expansion';
    const handle = await brokerWithSecret('SECRET', real);
    const outFile = join(tmp, 'expanded.txt');
    const code = await runExec({
      args: ['--b64', b64(`echo $SECRET > ${JSON.stringify(outFile)}`)],
      env: { SECRET: handle },
      sockPath: broker!.sockPath,
      stdio: 'ignore',
    });
    expect(code).toBe(0);
    expect(readFileSync(outFile, 'utf8').trim()).toBe(real);
  });

  it('a pipe (`printenv SECRET | cat`) runs the whole pipeline inside the inner shell so the piped consumer receives the real value', async () => {
    const real = 'sk-pipe-consumer';
    const handle = await brokerWithSecret('SECRET', real);
    const outFile = join(tmp, 'piped.txt');
    const code = await runExec({
      args: ['--b64', b64(`printenv SECRET | cat > ${JSON.stringify(outFile)}`)],
      env: { SECRET: handle },
      sockPath: broker!.sockPath,
      stdio: 'ignore',
    });
    expect(code).toBe(0);
    expect(readFileSync(outFile, 'utf8').trim()).toBe(real);
  });

  it('quotes/redirect (`echo "$SECRET" > $TMPFILE`) are parsed by the inner shell: the redirect target receives the real value', async () => {
    const real = 'sk-redirect-target';
    const handle = await brokerWithSecret('SECRET', real);
    const outFile = join(tmp, 'redirected.txt');
    const code = await runExec({
      args: ['--b64', b64('echo "$SECRET" > $TMPFILE')],
      env: { SECRET: handle, TMPFILE: outFile },
      sockPath: broker!.sockPath,
      stdio: 'ignore',
    });
    expect(code).toBe(0);
    expect(readFileSync(outFile, 'utf8').trim()).toBe(real);
  });

  it('e2e via the built binary: a base64-wrapped `tool --key $SECRET` yields the real value as the --key arg, never the handle', async () => {
    const real = 'sk-e2e-tool-flag';
    const handle = await brokerWithSecret('SECRET', real);
    const recordFile = join(tmp, 'e2e-argv.json');
    const tool = join(tmp, 'e2e-tool.mjs');
    writeFileSync(
      tool,
      `import { writeFileSync } from 'node:fs';
       writeFileSync(${JSON.stringify(recordFile)}, JSON.stringify(process.argv.slice(2)));
      `,
    );
    const cmd = `${JSON.stringify(process.execPath)} ${JSON.stringify(tool)} --key $SECRET`;
    await pexecFile(process.execPath, [BIN, 'exec', '--b64', b64(cmd)], {
      encoding: 'utf8',
      env: { ...process.env, SECRET: handle, CHAFF_SOCK: broker!.sockPath },
    });
    const argv = JSON.parse(readFileSync(recordFile, 'utf8')) as string[];
    expect(argv).toEqual(['--key', real]);
    expect(argv).not.toContain(handle);
  });
});

describe('ac-3: inner shell is bash, sourced from a single constant, documented', () => {
  it('exec spawns its inner shell as `bash -c <command>` (the spawned executable is bash, asserted via a recording shim)', async () => {
    // A recording shim named `bash` on PATH writes the argv it was invoked with,
    // proving exec spawns `bash -c <decoded command>`.
    const recordFile = join(tmp, 'shim-argv.json');
    const binDir = join(tmp, 'shimbin');
    mkdirSync(binDir, { recursive: true });
    const shim = join(binDir, INNER_SHELL);
    // A /bin/sh shim named `bash`: absolute interpreter, so it needs no PATH in
    // the child env. It writes each positional arg on its own line, proving the
    // spawned executable is `bash` and that it was invoked `bash -c <command>`.
    writeFileSync(
      shim,
      `#!/bin/sh\n: > ${JSON.stringify(recordFile)}\nfor a in "$@"; do printf '%s\\n' "$a" >> ${JSON.stringify(
        recordFile,
      )}; done\n`,
    );
    chmodSync(shim, 0o755);

    const handle = await brokerWithSecret('UNUSED', 'unused');
    const savedPath = process.env.PATH;
    // Prepend the shim dir so spawn(INNER_SHELL) resolves to our recording `bash`.
    process.env.PATH = `${binDir}:${savedPath ?? ''}`;
    try {
      const code = await runExec({
        args: ['--b64', b64('echo hello')],
        env: { PLACEHOLDER: handle, PATH: process.env.PATH },
        sockPath: broker!.sockPath,
        stdio: 'ignore',
      });
      expect(code).toBe(0);
    } finally {
      process.env.PATH = savedPath;
    }
    const argv = readFileSync(recordFile, 'utf8').split('\n').filter(Boolean);
    expect(argv).toEqual(['-c', 'echo hello']);
  });

  it('the inner shell choice is sourced from a single constant (INNER_SHELL) in exec.ts', () => {
    // One exported definition names the shell; it is bash.
    expect(INNER_SHELL).toBe('bash');
    // The exec.ts source spawns INNER_SHELL rather than a hard-coded literal at
    // the call site, so the constant is the single source of truth.
    const source = readFileSync(join(SRC_DIR, 'exec.ts'), 'utf8');
    expect(source).toMatch(/spawn\(\s*INNER_SHELL\b/);
  });

  it('manual: the bash choice and its rationale are documented in exec.ts where a maintainer will find them', () => {
    // Automated guard for the documentation AC: the module-level doc comment must
    // name bash AND explain the "match the harness shell" rationale, so the
    // decision is not an incidental mention. (Human still reads the prose.)
    const source = readFileSync(join(SRC_DIR, 'exec.ts'), 'utf8');
    expect(source).toContain('decision #2');
    expect(source.toLowerCase()).toContain('bash');
    expect(source).toMatch(/match(es|ing)? the (shell the )?harness/i);
  });
});

describe('ac-4: child gets real values; parent/harness keeps only handles', () => {
  it('child-reads-env leg: a child reading process.env.SECRET under exec gets the real value', async () => {
    const real = 'sk-ac4-child-env';
    const handle = await brokerWithSecret('SECRET', real);
    const outFile = join(tmp, 'ac4-child.txt');
    const code = await runExec({
      args: ['--b64', b64(`printenv SECRET > ${JSON.stringify(outFile)}`)],
      env: { SECRET: handle },
      sockPath: broker!.sockPath,
      stdio: 'ignore',
    });
    expect(code).toBe(0);
    expect(readFileSync(outFile, 'utf8').trim()).toBe(real);
  });

  it('tool-flag leg: a `tool --key $SECRET` decoded command receives the real value as the flag argument', async () => {
    const real = 'sk-ac4-tool-flag';
    const handle = await brokerWithSecret('SECRET', real);
    const recordFile = join(tmp, 'ac4-argv.json');
    const tool = join(tmp, 'ac4-tool.mjs');
    writeFileSync(
      tool,
      `import { writeFileSync } from 'node:fs';
       writeFileSync(${JSON.stringify(recordFile)}, JSON.stringify(process.argv.slice(2)));
      `,
    );
    const code = await runExec({
      args: [
        '--b64',
        b64(`${JSON.stringify(process.execPath)} ${JSON.stringify(tool)} --key $SECRET`),
      ],
      env: { SECRET: handle },
      sockPath: broker!.sockPath,
      stdio: 'ignore',
    });
    expect(code).toBe(0);
    expect(JSON.parse(readFileSync(recordFile, 'utf8'))).toEqual(['--key', real]);
  });

  it('parent-isolation leg: the inbound parent env still holds a handle for SECRET that is not the real value', async () => {
    const real = 'sk-ac4-parent-iso';
    const handle = await brokerWithSecret('SECRET', real);
    const parentEnv = { SECRET: handle };
    const childEnv = await resolveChildEnv(parentEnv, (h) => resolveViaBroker(broker!.sockPath, h));
    // Only the child env carries the resolved real value.
    expect(childEnv.SECRET).toBe(real);
    // The parent snapshot still holds the handle and does NOT equal the real value.
    expect(isHandle(parentEnv.SECRET)).toBe(true);
    expect(parentEnv.SECRET).not.toBe(real);
  });

  it('the real secret value never appears in exec own process.env after resolution', async () => {
    const real = 'sk-ac4-no-leak-into-process-env';
    const handle = await brokerWithSecret('SECRET', real);
    const savedSecret = process.env.SECRET;
    process.env.SECRET = handle;
    try {
      const childEnv = await resolveChildEnv({ SECRET: process.env.SECRET }, (h) =>
        resolveViaBroker(broker!.sockPath, h),
      );
      // Resolution wrote the real value only into the returned child env object.
      expect(childEnv.SECRET).toBe(real);
      // exec's own process.env entry for SECRET is still the handle, never the real value.
      expect(process.env.SECRET).toBe(handle);
      expect(process.env.SECRET).not.toBe(real);
    } finally {
      if (savedSecret === undefined) {
        delete process.env.SECRET;
      } else {
        process.env.SECRET = savedSecret;
      }
    }
  });

  it('e2e via the built binary: a single invocation shows the child env read AND a --key $SECRET arg get the real value, while exec received the handle as input', async () => {
    const real = 'sk-ac4-e2e-all-legs';
    const handle = await brokerWithSecret('SECRET', real);
    const envFile = join(tmp, 'ac4-e2e-env.txt');
    const argFile = join(tmp, 'ac4-e2e-arg.txt');
    const tool = join(tmp, 'ac4-e2e-tool.mjs');
    // The tool records both process.env.SECRET (env-read leg) and its --key argv
    // (tool-flag leg) in one run.
    writeFileSync(
      tool,
      `import { writeFileSync } from 'node:fs';
       writeFileSync(${JSON.stringify(envFile)}, process.env.SECRET ?? '');
       writeFileSync(${JSON.stringify(argFile)}, process.argv[3] ?? '');
      `,
    );
    const cmd = `${JSON.stringify(process.execPath)} ${JSON.stringify(tool)} --key $SECRET`;
    await pexecFile(process.execPath, [BIN, 'exec', '--b64', b64(cmd)], {
      encoding: 'utf8',
      env: { ...process.env, SECRET: handle, CHAFF_SOCK: broker!.sockPath },
    });
    // Both legs see the real value...
    expect(readFileSync(envFile, 'utf8')).toBe(real);
    expect(readFileSync(argFile, 'utf8')).toBe(real);
    // ...while the value the harness assigned to SECRET (handed to exec) was the handle.
    expect(isHandle(handle)).toBe(true);
    expect(handle).not.toBe(real);
  });
});
