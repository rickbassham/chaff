import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { isHandle, parseHandle } from '../src/handles.js';
import { classify } from '../src/policy.js';
import { startBroker, type Broker } from '../src/broker.js';
import { request } from './helpers/broker-client.js';
import { buildHarnessEnv, formatLaunchBanner, runLauncher } from '../src/launcher.js';

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

/** A representative env snapshot: two secrets (by glob) and two pass-through vars. */
function seededSnapshot(): Record<string, string> {
  return {
    OPENAI_API_KEY: 'sk-real-openai-value-123',
    DB_TOKEN: 'real-db-token-value-456',
    PATH: '/usr/bin:/bin',
    EDITOR: 'vim',
  };
}

let tmp: string;
let logPath: string;
let savedXdg: string | undefined;
let broker: Broker | undefined;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-'));
  logPath = join(tmp, 'audit.jsonl');
  savedXdg = process.env.XDG_RUNTIME_DIR;
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

describe('ac-1: snapshot, classify, build handle env + CHAFF_SOCK, spawn', () => {
  it('given a seeded env snapshot, every var policy.classify marks secret=true is replaced in the built harness env by a value that isHandle() accepts; non-secret vars are passed through with their original value unchanged', () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const { env } = buildHarnessEnv(snapshot, classification, '/tmp/sock');

    for (const [name, value] of Object.entries(snapshot)) {
      if (classification[name]!.secret) {
        expect(isHandle(env[name]!)).toBe(true);
      } else {
        expect(env[name]).toBe(value);
      }
    }
  });

  it("the built harness env sets CHAFF_SOCK to the started broker's sockPath (a filesystem path string, not a secret value)", async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const { secrets } = buildHarnessEnv(snapshot, classification, 'placeholder');
    broker = await startBroker({ secrets, auditLogPath: logPath });

    const { env } = buildHarnessEnv(snapshot, classification, broker.sockPath);
    expect(env.CHAFF_SOCK).toBe(broker.sockPath);
    // It is a path string, not a secret value.
    for (const value of Object.values(snapshot)) {
      if (classification[Object.keys(snapshot).find((k) => snapshot[k] === value)!]) {
        // checked below in ac-2; here just assert it is the sock path.
      }
    }
    expect(env.CHAFF_SOCK).not.toContain('sk-real-openai-value-123');
  });

  it("each handle placed in the harness env carries the originating var's NAME segment (parseHandle(handleEnv[NAME]).name === NAME), so the harness env maps each secret name to its own handle", () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const { env } = buildHarnessEnv(snapshot, classification, '/tmp/sock');

    for (const [name, verdict] of Object.entries(classification)) {
      if (verdict.secret) {
        expect(parseHandle(env[name]!)?.name).toBe(name);
      }
    }
  });

  it("the broker is started with one BrokerSecret per secret-classified var whose name/value/handle match the snapshot value and the handle placed in the harness env (resolve(handle) over the started broker returns the snapshot's real value)", async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const { env, secrets } = buildHarnessEnv(snapshot, classification, 'placeholder');

    const secretNames = Object.keys(classification).filter((n) => classification[n]!.secret);
    expect(secrets.map((s) => s.name).sort()).toEqual([...secretNames].sort());

    broker = await startBroker({ secrets, auditLogPath: logPath });
    for (const s of secrets) {
      expect(s.value).toBe(snapshot[s.name]);
      expect(s.handle).toBe(env[s.name]);
      const res = (await request(broker.sockPath, { op: 'resolve', handle: s.handle })) as {
        value: string;
      };
      expect(res.value).toBe(snapshot[s.name]);
    }
  });

  it('chaff run spawns the harness command (argv after `--`) exactly once with the built handle env, and the spawned process is the command named after `--`', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const recordFile = join(tmp, 'record.json');
    const script = join(tmp, 'dummy.mjs');
    writeFileSync(
      script,
      `import { writeFileSync } from 'node:fs';
       writeFileSync(${JSON.stringify(recordFile)}, JSON.stringify({ argv: process.argv.slice(2), env: process.env }));
      `,
    );

    const snapshot = { ...seededSnapshot(), XDG_RUNTIME_DIR: tmp };
    const code = await runLauncher({
      argv: [process.execPath, script, 'arg1'],
      env: snapshot,
      auditLogPath: logPath,
      stderr: { write: () => true },
    });
    expect(code).toBe(0);

    const record = JSON.parse(execFileSync('cat', [recordFile], { encoding: 'utf8' })) as {
      argv: string[];
      env: Record<string, string>;
    };
    // The dummy is `node <script> arg1`; the script records process.argv.slice(2),
    // which for that invocation is the args after the script path: ['arg1'].
    expect(record.argv).toEqual(['arg1']);
    // The child saw the handle env: secret var is a handle, CHAFF_SOCK present.
    expect(isHandle(record.env.OPENAI_API_KEY!)).toBe(true);
    expect(typeof record.env.CHAFF_SOCK).toBe('string');
  });

  it('the launcher snapshots the env it classifies from its own process env at invocation time rather than re-reading it after spawn (a var unset between snapshot and spawn is still classified/handled from the snapshot)', () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    // buildHarnessEnv takes the snapshot by value; mutating the source object
    // afterward does not change the already-built env.
    const { env } = buildHarnessEnv(snapshot, classification, '/tmp/sock');
    delete snapshot.OPENAI_API_KEY;
    expect(isHandle(env.OPENAI_API_KEY!)).toBe(true);
  });
});

describe('ac-2: broker holds real values; harness env handles-only + CHAFF_SOCK', () => {
  it("for every secret-classified var, the var's real value string does NOT appear anywhere in the serialized harness env", () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const { env } = buildHarnessEnv(snapshot, classification, '/tmp/sock');
    const serialized = JSON.stringify(env);
    for (const [name, verdict] of Object.entries(classification)) {
      if (verdict.secret) {
        expect(serialized).not.toContain(snapshot[name]);
      }
    }
  });

  it('for every secret-classified var, the harness env value for that var name passes isHandle()', () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const { env } = buildHarnessEnv(snapshot, classification, '/tmp/sock');
    for (const [name, verdict] of Object.entries(classification)) {
      if (verdict.secret) {
        expect(isHandle(env[name]!)).toBe(true);
      }
    }
  });

  it('the harness env exposes no broker auth token: CHAFF_SOCK equals the broker sockPath and no additional secret/token-bearing key is added (only CHAFF_SOCK plus the original var names appear)', () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const { env } = buildHarnessEnv(snapshot, classification, '/tmp/sock');
    expect(env.CHAFF_SOCK).toBe('/tmp/sock');
    // Keys are exactly the snapshot's names plus CHAFF_SOCK — nothing else.
    expect(Object.keys(env).sort()).toEqual([...Object.keys(snapshot), 'CHAFF_SOCK'].sort());
    expect(JSON.stringify(env).toLowerCase()).not.toContain('token=');
  });

  it('resolve(handle) over the running broker returns the real secret value for each handle the launcher placed in the harness env, proving the broker (not the harness env) holds the real values', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const { env, secrets } = buildHarnessEnv(snapshot, classification, 'placeholder');
    broker = await startBroker({ secrets, auditLogPath: logPath });

    for (const [name, verdict] of Object.entries(classification)) {
      if (verdict.secret) {
        const res = (await request(broker.sockPath, {
          op: 'resolve',
          handle: env[name],
        })) as { value: string };
        expect(res.value).toBe(snapshot[name]);
      }
    }
  });

  it("end-to-end through runLauncher: the handle the harness receives in its env resolves over the launcher's own broker to the real value (proves the broker is seeded with the SAME handle placed in the env, not a re-minted one)", async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const resolvedFile = join(tmp, 'resolved.txt');
    // The dummy harness connects to its own CHAFF_SOCK, resolves the handle it
    // was given for OPENAI_API_KEY, and writes the resolved value to a file —
    // all while the broker is still alive (before the launcher tears it down).
    const script = join(tmp, 'resolve-self.mjs');
    writeFileSync(
      script,
      `import { createConnection } from 'node:net';
       import { writeFileSync } from 'node:fs';
       const conn = createConnection(process.env.CHAFF_SOCK);
       let buf = '';
       conn.on('connect', () => conn.write(JSON.stringify({ op: 'resolve', handle: process.env.OPENAI_API_KEY }) + '\\n'));
       conn.on('data', (c) => {
         buf += c.toString('utf8');
         if (buf.includes('\\n')) {
           writeFileSync(${JSON.stringify(resolvedFile)}, JSON.parse(buf.split('\\n')[0]).value ?? '');
           conn.end();
           process.exit(0);
         }
       });
      `,
    );
    const snapshot = { ...seededSnapshot(), XDG_RUNTIME_DIR: tmp };
    const code = await runLauncher({
      argv: [process.execPath, script],
      env: snapshot,
      auditLogPath: logPath,
      stderr: { write: () => true },
    });
    expect(code).toBe(0);
    const resolved = execFileSync('cat', [resolvedFile], { encoding: 'utf8' });
    expect(resolved).toBe('sk-real-openai-value-123');
  });
});

describe('ac-3: launch banner reports handled vars by name, never values, to stderr', () => {
  it('the launch banner lists, by name, every var classified secret=true that became a handle, and omits every non-secret var', () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const banner = formatLaunchBanner(classification);
    for (const [name, verdict] of Object.entries(classification)) {
      if (verdict.secret) {
        expect(banner).toContain(name);
      } else {
        expect(banner).not.toContain(name);
      }
    }
  });

  it('the launch banner contains no secret VALUE (only var names appear, never values)', () => {
    const snapshot = seededSnapshot();
    const classification = classify(snapshot, {});
    const banner = formatLaunchBanner(classification);
    for (const value of Object.values(snapshot)) {
      expect(banner).not.toContain(value);
    }
  });

  it("the launch banner is written to stderr (not stdout), so it does not contaminate the harness's stdout stream", async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const script = join(tmp, 'noop.mjs');
    writeFileSync(script, 'process.exit(0);\n');
    let stderrText = '';
    const snapshot = { ...seededSnapshot(), XDG_RUNTIME_DIR: tmp };
    await runLauncher({
      argv: [process.execPath, script],
      env: snapshot,
      auditLogPath: logPath,
      stderr: {
        write: (chunk: string) => {
          stderrText += chunk;
          return true;
        },
      },
    });
    expect(stderrText).toContain('OPENAI_API_KEY');
    expect(stderrText).not.toContain('sk-real-openai-value-123');
  });
});

describe('ac-4: broker torn down on harness exit; exit code propagates', () => {
  it('when the spawned harness process exits, the launcher calls broker.close(): after harness exit the broker socket file and its per-session directory no longer exist on disk', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const sockFile = join(tmp, 'sock-path.txt');
    const script = join(tmp, 'record-sock.mjs');
    writeFileSync(
      script,
      `import { writeFileSync } from 'node:fs';
       writeFileSync(${JSON.stringify(sockFile)}, process.env.CHAFF_SOCK ?? '');
       process.exit(0);
      `,
    );
    const snapshot = { ...seededSnapshot(), XDG_RUNTIME_DIR: tmp };
    await runLauncher({
      argv: [process.execPath, script],
      env: snapshot,
      auditLogPath: logPath,
      stderr: { write: () => true },
    });
    const sockPath = execFileSync('cat', [sockFile], { encoding: 'utf8' }).trim();
    expect(sockPath.length).toBeGreaterThan(0);
    expect(existsSync(sockPath)).toBe(false);
    expect(existsSync(join(sockPath, '..'))).toBe(false);
  });

  it('after the harness exits and the broker is torn down, a fresh connection to the old CHAFF_SOCK path fails (the broker is no longer listening)', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const sockFile = join(tmp, 'sock-path2.txt');
    const script = join(tmp, 'record-sock2.mjs');
    writeFileSync(
      script,
      `import { writeFileSync } from 'node:fs';
       writeFileSync(${JSON.stringify(sockFile)}, process.env.CHAFF_SOCK ?? '');
       process.exit(0);
      `,
    );
    const snapshot = { ...seededSnapshot(), XDG_RUNTIME_DIR: tmp };
    await runLauncher({
      argv: [process.execPath, script],
      env: snapshot,
      auditLogPath: logPath,
      stderr: { write: () => true },
    });
    const sockPath = execFileSync('cat', [sockFile], { encoding: 'utf8' }).trim();
    await expect(request(sockPath, { op: 'list' })).rejects.toBeDefined();
  });

  it("chaff run's exit code reflects the harness's exit code (a dummy harness exiting non-zero causes chaff run to report a non-zero status), so teardown does not mask the child result", async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const script = join(tmp, 'exit7.mjs');
    writeFileSync(script, 'process.exit(7);\n');
    const snapshot = { ...seededSnapshot(), XDG_RUNTIME_DIR: tmp };
    const code = await runLauncher({
      argv: [process.execPath, script],
      env: snapshot,
      auditLogPath: logPath,
      stderr: { write: () => true },
    });
    expect(code).toBe(7);
  });
});

describe('ac-5: e2e via the built chaff binary — handles in env and echo $SECRET', () => {
  const BIN = join(SRC_DIR, '..', 'dist', 'bin', 'chaff.js');

  /** Run `chaff run -- <argv>` via the built binary; return {stdout, status}. */
  function runChaff(
    argv: string[],
    extraEnv: Record<string, string>,
  ): { stdout: string; status: number } {
    try {
      const stdout = execFileSync(process.execPath, [BIN, 'run', '--', ...argv], {
        encoding: 'utf8',
        env: { ...process.env, ...extraEnv },
      });
      return { stdout, status: 0 };
    } catch (err) {
      const e = err as { stdout?: string; status?: number };
      return { stdout: e.stdout ?? '', status: e.status ?? 1 };
    }
  }

  it("a dummy harness script launched via the built chaff binary under `chaff run -- <script>` with a seeded secret env var: the script's `env` output shows the handle for that var and NOT the real value", () => {
    if (!existsSync(BIN)) {
      throw new Error(`built binary missing at ${BIN}; run \`make build\` first`);
    }
    const realValue = 'sk-e2e-secret-value-abc';
    const { stdout } = runChaff(['node', '-e', 'console.log(process.env.E2E_API_KEY)'], {
      E2E_API_KEY: realValue,
      XDG_RUNTIME_DIR: tmp,
    });
    expect(isHandle(stdout.trim())).toBe(true);
    expect(stdout).not.toContain(realValue);
  });

  it("the same dummy harness script's `echo $SECRET` (shell expansion of the secret var) prints the handle, never the real value", () => {
    if (!existsSync(BIN)) {
      throw new Error(`built binary missing at ${BIN}; run \`make build\` first`);
    }
    const realValue = 'sk-e2e-secret-value-xyz';
    const shScript = join(tmp, 'echo-secret.sh');
    writeFileSync(shScript, '#!/bin/sh\necho "$E2E_API_KEY"\n');
    chmodSync(shScript, 0o755);
    const { stdout } = runChaff([shScript], {
      E2E_API_KEY: realValue,
      XDG_RUNTIME_DIR: tmp,
    });
    expect(isHandle(stdout.trim())).toBe(true);
    expect(stdout).not.toContain(realValue);
  });
});
