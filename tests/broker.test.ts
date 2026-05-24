import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, statSync, mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createConnection } from 'node:net';
import { execFileSync } from 'node:child_process';
import { formatHandle } from '../src/handles.js';
import { startBroker, type Broker, type BrokerSecret } from '../src/broker.js';

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

/** Build a fresh secret with a handle for `name`/`value`. */
function secret(name: string, value: string): BrokerSecret {
  return { name, value, handle: formatHandle(name) };
}

/**
 * Compile the broker source (and its in-package deps) to plain ESM JS in a
 * fresh temp dir, returning that dir. Used by the spawned-child teardown test,
 * which needs to run the real broker in a separate Node process without a TS
 * loader. Built fresh from src so it never relies on a stale dist/.
 */
function compileSrcToTemp(): string {
  const outDir = mkdtempSync(join(tmpdir(), 'chaff-broker-compiled-'));
  const tsc = join(SRC_DIR, '..', 'node_modules', '.bin', 'tsc');
  execFileSync(
    tsc,
    [
      join(SRC_DIR, 'broker.ts'),
      join(SRC_DIR, 'handles.ts'),
      join(SRC_DIR, 'audit.ts'),
      '--module',
      'NodeNext',
      '--moduleResolution',
      'NodeNext',
      '--target',
      'ES2022',
      '--outDir',
      outDir,
    ],
    { stdio: 'pipe' },
  );
  return outDir;
}

/**
 * Send one newline-delimited JSON request to a broker socket and resolve with
 * the parsed newline-delimited JSON response.
 */
function request(sockPath: string, req: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const conn = createConnection(sockPath);
    let buf = '';
    conn.on('error', reject);
    conn.on('connect', () => {
      conn.write(JSON.stringify(req) + '\n');
    });
    conn.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl !== -1) {
        const line = buf.slice(0, nl);
        conn.end();
        try {
          resolve(JSON.parse(line));
        } catch (err) {
          reject(err as Error);
        }
      }
    });
  });
}

let tmp: string;
let logPath: string;
let broker: Broker | undefined;
let savedXdg: string | undefined;

beforeEach(() => {
  // Short prefix: this dir becomes $XDG_RUNTIME_DIR, under which the broker
  // creates its own session dir + socket. AF_UNIX paths cap near 104 bytes, so
  // the test's runtime root must leave room for the broker's segments.
  tmp = mkdtempSync(join(tmpdir(), 'cbt-'));
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

describe('ac-1: socket server, fs-perms trust boundary', () => {
  it('starting the broker creates a listening AF_UNIX server whose socket path resides inside a freshly-created per-session directory (not the bare runtime root)', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });

    expect(existsSync(broker.sockPath)).toBe(true);
    // The socket sits inside a session dir, which itself is inside the runtime
    // root — not directly in the runtime root.
    const sessionDir = join(broker.sockPath, '..');
    expect(statSync(sessionDir).isDirectory()).toBe(true);
    expect(join(sessionDir, '..')).not.toBe(broker.sockPath);
    // Session dir is under the runtime root, but is not the runtime root itself.
    expect(broker.sockPath.startsWith(tmp)).toBe(true);
    expect(join(sessionDir)).not.toBe(tmp);

    // It is actually listening: a request gets a response.
    const res = (await request(broker.sockPath, { op: 'list' })) as { names: string[] };
    expect(res.names).toContain('A_KEY');
  });

  it('the per-session directory is created with mode 0700 (stat st_mode & 0o777 === 0o700), verified after umask is set to a permissive value to prove the broker forces the mode rather than relying on inherited umask', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const prevUmask = process.umask(0o000);
    try {
      broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });
      const sessionDir = join(broker.sockPath, '..');
      expect(statSync(sessionDir).mode & 0o777).toBe(0o700);
    } finally {
      process.umask(prevUmask);
    }
  });

  it('the socket file is created with mode 0600 (stat st_mode & 0o777 === 0o600), verified after a permissive umask to prove the broker forces the mode', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const prevUmask = process.umask(0o000);
    try {
      broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });
      expect(statSync(broker.sockPath).mode & 0o777).toBe(0o600);
    } finally {
      process.umask(prevUmask);
    }
  });

  it('with $XDG_RUNTIME_DIR set, the session dir is created under that directory; with $XDG_RUNTIME_DIR unset, it falls back under /tmp (os.tmpdir)', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });
    expect(broker.sockPath.startsWith(tmp)).toBe(true);
    broker.close();
    broker = undefined;

    delete process.env.XDG_RUNTIME_DIR;
    broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });
    expect(broker.sockPath.startsWith(tmpdir())).toBe(true);
  });

  it('the broker registers no peer-credential / connection-uid check: a connection from the same process is accepted and served purely on the basis of socket access (documents decision #1 — fs-perms is the only gate)', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });
    // A plain same-process connection with no credentials of any kind is served.
    const res = (await request(broker.sockPath, { op: 'list' })) as { names: string[] };
    expect(res.names).toEqual(['A_KEY']);
  });
});

describe('ac-2: ops resolve / list / redaction-set', () => {
  it("resolve(handle) for a known handle returns that secret's real value over the socket", async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const s = secret('OPENAI_API_KEY', 'sk-real-value-123');
    broker = await startBroker({ secrets: [s], auditLogPath: logPath });

    const res = (await request(broker.sockPath, { op: 'resolve', handle: s.handle })) as {
      value: string;
    };
    expect(res.value).toBe('sk-real-value-123');
  });

  it('resolve of an unknown/unregistered handle returns an error/absent result and does NOT return any other secret\'s value', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });

    const unknown = formatHandle('NOT_REGISTERED');
    const res = (await request(broker.sockPath, { op: 'resolve', handle: unknown })) as {
      value?: string;
      error?: string;
    };
    expect(res.value).toBeUndefined();
    expect(res.error).toBeDefined();
    expect(JSON.stringify(res)).not.toContain('val-a');
  });

  it('list() returns the set of secret NAMES the broker holds and contains none of the secret values (assert each real value string is absent from the serialized list response)', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const secrets = [secret('A_KEY', 'val-a-secret'), secret('B_TOKEN', 'val-b-secret')];
    broker = await startBroker({ secrets, auditLogPath: logPath });

    const res = (await request(broker.sockPath, { op: 'list' })) as { names: string[] };
    expect(res.names.sort()).toEqual(['A_KEY', 'B_TOKEN']);
    const serialized = JSON.stringify(res);
    for (const s of secrets) {
      expect(serialized).not.toContain(s.value);
    }
  });

  it('redaction-set() returns an object with `patterns` and `handles` keys whose contents are precomputed at broker construction (the same call returns equal results without re-deriving per request)', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    broker = await startBroker({
      secrets: [secret('A_KEY', 'val-a'), secret('B_TOKEN', 'val-b')],
      auditLogPath: logPath,
    });

    const first = (await request(broker.sockPath, { op: 'redaction-set' })) as {
      patterns: string[];
      handles: string[];
    };
    expect(first).toHaveProperty('patterns');
    expect(first).toHaveProperty('handles');
    const second = (await request(broker.sockPath, { op: 'redaction-set' })) as unknown;
    expect(second).toEqual(first);
  });

  it("redaction-set().handles contains the handle strings for the held secrets and redaction-set().patterns contains the secrets' real values (the precomputed pattern source for the scrubber)", async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const secrets = [secret('A_KEY', 'val-a-secret'), secret('B_TOKEN', 'val-b-secret')];
    broker = await startBroker({ secrets, auditLogPath: logPath });

    const res = (await request(broker.sockPath, { op: 'redaction-set' })) as {
      patterns: string[];
      handles: string[];
    };
    for (const s of secrets) {
      expect(res.handles).toContain(s.handle);
      expect(res.patterns).toContain(s.value);
    }
  });
});

describe('ac-3: every resolve is audit-logged', () => {
  it("a single resolve(handle) call appends exactly one audit entry with op==='resolve' and secretName equal to the resolved secret's name, via audit.ts writeAuditEntry", async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const s = secret('OPENAI_API_KEY', 'sk-value');
    broker = await startBroker({ secrets: [s], auditLogPath: logPath });

    await request(broker.sockPath, { op: 'resolve', handle: s.handle });

    const lines = readFileSync(logPath, 'utf8')
      .split('\n')
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l) as { ts: string; op: string; secretName: string });
    expect(lines).toHaveLength(1);
    expect(lines[0]!.op).toBe('resolve');
    expect(lines[0]!.secretName).toBe('OPENAI_API_KEY');
  });

  it('N successive resolve calls produce N audit entries in call order, each {ts, op, secretName}', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const secrets = [
      secret('A_KEY', 'val-a'),
      secret('B_TOKEN', 'val-b'),
      secret('C_SECRET', 'val-c'),
    ];
    broker = await startBroker({ secrets, auditLogPath: logPath });

    for (const s of secrets) {
      await request(broker.sockPath, { op: 'resolve', handle: s.handle });
    }

    const lines = readFileSync(logPath, 'utf8')
      .split('\n')
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l) as { ts: string; op: string; secretName: string });
    expect(lines).toHaveLength(3);
    expect(lines.map((e) => e.secretName)).toEqual(['A_KEY', 'B_TOKEN', 'C_SECRET']);
    for (const e of lines) {
      expect(Object.keys(e).sort()).toEqual(['op', 'secretName', 'ts']);
      expect(e.op).toBe('resolve');
    }
  });

  it('no audit entry written for a resolve contains the secret VALUE (assert the resolved value string is absent from the audit log file)', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const s = secret('A_KEY', 'sk-super-secret-value-do-not-leak');
    broker = await startBroker({ secrets: [s], auditLogPath: logPath });

    await request(broker.sockPath, { op: 'resolve', handle: s.handle });

    const raw = readFileSync(logPath, 'utf8');
    expect(raw).not.toContain(s.value);
  });
});

describe('ac-4: only CHAFF_SOCK exported, never a token/secret', () => {
  it('the broker\'s published connection info exposes only the socket path as CHAFF_SOCK and exposes no auth token field', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });

    expect(Object.keys(broker.env)).toEqual(['CHAFF_SOCK']);
    expect(broker.env.CHAFF_SOCK).toBe(broker.sockPath);
    const serialized = JSON.stringify(broker.env).toLowerCase();
    expect(serialized).not.toContain('token');
  });

  it('the value the broker exports for client connection (CHAFF_SOCK) contains no secret value and no secret token (assert real secret values are absent from the exported string)', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const s = secret('A_KEY', 'val-a-secret-value');
    broker = await startBroker({ secrets: [s], auditLogPath: logPath });

    expect(broker.env.CHAFF_SOCK).not.toContain(s.value);
    expect(broker.env.CHAFF_SOCK).not.toContain(s.handle);
  });
});

describe('ac-5: torn down on process exit — no stale socket or orphan', () => {
  it('calling the broker\'s close/teardown removes the socket file and the per-session directory from disk', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });
    const sockPath = broker.sockPath;
    const sessionDir = join(sockPath, '..');
    expect(existsSync(sockPath)).toBe(true);

    broker.close();
    broker = undefined;

    expect(existsSync(sockPath)).toBe(false);
    expect(existsSync(sessionDir)).toBe(false);
  });

  it('after teardown the server is no longer listening (a fresh connect to the old socket path fails)', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });
    const sockPath = broker.sockPath;
    broker.close();
    broker = undefined;

    await expect(request(sockPath, { op: 'list' })).rejects.toBeDefined();
  });

  it('a broker started and torn down within a spawned child process leaves no socket file or session dir behind after the child exits (proves teardown fires on process exit, not just explicit close)', () => {
    const childRuntimeDir = mkdtempSync(join(tmpdir(), 'chaff-broker-child-'));
    const childLog = join(childRuntimeDir, 'audit.jsonl');
    // Compile the broker (and its deps) to plain JS in a temp dir so a spawned
    // Node process can run it without a TS loader. The child starts a broker
    // and exits WITHOUT calling close(); only the process-exit teardown can
    // remove the socket + session dir, which is exactly what this asserts.
    const outDir = compileSrcToTemp();
    try {
      const brokerJs = join(outDir, 'broker.js');
      const handlesJs = join(outDir, 'handles.js');
      const script = `
        import { startBroker } from ${JSON.stringify(brokerJs)};
        import { formatHandle } from ${JSON.stringify(handlesJs)};
        process.env.XDG_RUNTIME_DIR = ${JSON.stringify(childRuntimeDir)};
        const b = await startBroker({
          secrets: [{ name: 'A_KEY', value: 'val-a', handle: formatHandle('A_KEY') }],
          auditLogPath: ${JSON.stringify(childLog)},
        });
        console.log(b.sockPath);
        // Exit without calling close(); on-exit handler must clean up.
        process.exit(0);
      `;
      const out = execFileSync(process.execPath, ['--input-type=module', '-e', script], {
        encoding: 'utf8',
      });
      const sockPath = out.trim().split('\n').pop()!;
      const sessionDir = join(sockPath, '..');
      expect(existsSync(sockPath)).toBe(false);
      expect(existsSync(sessionDir)).toBe(false);
    } finally {
      rmSync(childRuntimeDir, { recursive: true, force: true });
      rmSync(outDir, { recursive: true, force: true });
    }
  });
});

describe('ac-6: explicit perms + resolve/list summary assertions', () => {
  it('explicit assertion that the session dir is 0700 and the socket is 0600 — the exact mode bits that restrict access to the owning uid (group/other have no access), satisfying the AC\'s same-uid-perms requirement', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    broker = await startBroker({ secrets: [secret('A_KEY', 'val-a')], auditLogPath: logPath });
    const sessionDir = join(broker.sockPath, '..');

    const dirMode = statSync(sessionDir).mode & 0o777;
    const sockMode = statSync(broker.sockPath).mode & 0o777;
    expect(dirMode).toBe(0o700);
    expect(sockMode).toBe(0o600);
    // group/other have no bits set.
    expect(dirMode & 0o077).toBe(0);
    expect(sockMode & 0o077).toBe(0);
  });

  it('resolve returns the value test (covered by ac-2): resolve(handle) returns the real secret value', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const s = secret('A_KEY', 'the-real-value');
    broker = await startBroker({ secrets: [s], auditLogPath: logPath });

    const res = (await request(broker.sockPath, { op: 'resolve', handle: s.handle })) as {
      value: string;
    };
    expect(res.value).toBe('the-real-value');
  });

  it('list returns names but not values test (covered by ac-2): list() includes names and excludes every real value', async () => {
    process.env.XDG_RUNTIME_DIR = tmp;
    const secrets = [secret('A_KEY', 'value-aaa'), secret('B_TOKEN', 'value-bbb')];
    broker = await startBroker({ secrets, auditLogPath: logPath });

    const res = (await request(broker.sockPath, { op: 'list' })) as { names: string[] };
    expect(res.names.sort()).toEqual(['A_KEY', 'B_TOKEN']);
    const serialized = JSON.stringify(res);
    for (const s of secrets) {
      expect(serialized).not.toContain(s.value);
    }
  });
});
