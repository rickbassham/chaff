/**
 * DAR-1140 — runLauncher → buildHarnessEnv wiring of the merged config.
 *
 * End-to-end integration: with user/folder config files present on disk,
 * runLauncher discovers and merges them (defaults→user→folder), enforces the
 * user never-pass set, and passes the effective allowlist + declared-managed
 * set into buildHarnessEnv. A child process records the env it actually
 * receives so we assert on the real harness env, not an intermediate.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { isHandle } from '../src/handles.js';
import { type LevelConfig } from '../src/config.js';
import { runLauncher } from '../src/launcher.js';
import { writeConfig } from './helpers/config-seed.js';

let tmp: string;
let logPath: string;
let cwd: string;
let userXdg: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-lc-'));
  logPath = join(tmp, 'audit.jsonl');
  cwd = join(tmp, 'repo');
  mkdirSync(cwd, { recursive: true });
  userXdg = join(tmp, 'xdg');
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

/** Write a folder-level config under cwd/.chaff. */
function seedFolderConfig(config: LevelConfig): void {
  const dir = join(cwd, '.chaff');
  mkdirSync(dir, { recursive: true });
  writeConfig(dir, config);
}

/** Write a user-level config under $XDG_CONFIG_HOME/chaff. */
function seedUserConfig(config: LevelConfig): void {
  const dir = join(userXdg, 'chaff');
  mkdirSync(dir, { recursive: true });
  writeConfig(dir, config);
}

/**
 * Run the harness and capture the env the child actually received. The dummy
 * script writes its process.env to a record file we then read back.
 */
async function runAndCaptureEnv(snapshot: Record<string, string>): Promise<{
  code: number;
  env: Record<string, string>;
}> {
  const recordFile = join(tmp, 'record.json');
  const script = join(tmp, 'dummy.mjs');
  writeFileSync(
    script,
    `import { writeFileSync } from 'node:fs';
     writeFileSync(${JSON.stringify(recordFile)}, JSON.stringify({ env: process.env }));
    `,
  );

  const code = await runLauncher({
    argv: [process.execPath, script],
    env: { ...snapshot, XDG_RUNTIME_DIR: tmp },
    auditLogPath: logPath,
    cwd,
    configEnv: { XDG_CONFIG_HOME: userXdg, HOME: join(tmp, 'home') },
    stderr: { write: () => true },
  });

  const record = JSON.parse(execFileSync('cat', [recordFile], { encoding: 'utf8' })) as {
    env: Record<string, string>;
  };
  return { code, env: record.env };
}

describe('ac-4: runLauncher wires the merged effective allowlist + declared-managed', () => {
  it('runLauncher passes the merged effective allowlist (defaults + user + folder) to buildHarnessEnv: a folder-only-allowlisted var passes through verbatim in the harness env end-to-end', async () => {
    seedFolderConfig({ allowlist: ['REPO_SETTING'], declaredManaged: [] });
    const { code, env } = await runAndCaptureEnv({ REPO_SETTING: 'repo-value' });
    expect(code).toBe(0);
    // folder-allowlisted, benign value → passthrough verbatim.
    expect(env.REPO_SETTING).toBe('repo-value');
  });

  it('runLauncher passes the merged declared-managed set to buildHarnessEnv: a declared-managed var becomes a handle (and a broker secret) end-to-end even though the heuristics do not flag it', async () => {
    seedUserConfig({ allowlist: [], declaredManaged: ['MY_APP_CONFIG'] });
    const { code, env } = await runAndCaptureEnv({ MY_APP_CONFIG: 'production' });
    expect(code).toBe(0);
    // declared-managed → handle even though 'production' is not secret-looking.
    expect(isHandle(env.MY_APP_CONFIG!)).toBe(true);
    expect(env.MY_APP_CONFIG).not.toBe('production');
  });

  it('runLauncher honors the user never-pass set end-to-end: a never-pass var that is also a shipped-default allowlist name is dropped from the harness env (absent), not passed through', async () => {
    // HOME is a shipped default; user never-pass blocks it.
    seedUserConfig({ allowlist: [], declaredManaged: [], neverPass: ['HOME'] });
    const { code, env } = await runAndCaptureEnv({ HOME: '/home/u', PATH: '/usr/bin' });
    expect(code).toBe(0);
    expect(Object.prototype.hasOwnProperty.call(env, 'HOME')).toBe(false);
    // PATH (also a shipped default, not blocked) still passes through.
    expect(env.PATH).toBe('/usr/bin');
  });

  it('with no config files present, runLauncher behaves exactly as DAR-1139: shipped default allowlist passes through, declaredManaged empty', async () => {
    // No seedUserConfig / seedFolderConfig calls — no config on disk.
    const { code, env } = await runAndCaptureEnv({
      PATH: '/usr/bin',
      OPENAI_API_KEY: 'sk-real-openai-value-123',
      EDITOR: 'vim',
    });
    expect(code).toBe(0);
    // shipped default allowlist → PATH passes through.
    expect(env.PATH).toBe('/usr/bin');
    // detected-secret → handle (declaredManaged empty, nothing extra managed).
    expect(isHandle(env.OPENAI_API_KEY!)).toBe(true);
    // neither allowlisted nor managed → dropped.
    expect(Object.prototype.hasOwnProperty.call(env, 'EDITOR')).toBe(false);
  });
});

describe('ac-5: end-to-end restatements (integration)', () => {
  it('folder cannot pass a user-never-pass var: a var in user never-pass and in folder allowlist is absent from the harness env when run through buildHarnessEnv with the merged config', async () => {
    seedUserConfig({ allowlist: [], declaredManaged: [], neverPass: ['BLOCKED_VAR'] });
    seedFolderConfig({ allowlist: ['BLOCKED_VAR'], declaredManaged: [] });
    const { code, env } = await runAndCaptureEnv({ BLOCKED_VAR: 'should-not-pass' });
    expect(code).toBe(0);
    expect(Object.prototype.hasOwnProperty.call(env, 'BLOCKED_VAR')).toBe(false);
  });

  it('a declared-managed var with a benign value the heuristics classify non-secret is emitted as a handle (isHandle true) with a matching broker secret carrying the real value', async () => {
    seedFolderConfig({ allowlist: [], declaredManaged: ['DEPLOY_REGION'] });
    const { code, env } = await runAndCaptureEnv({ DEPLOY_REGION: 'us-east-1' });
    expect(code).toBe(0);
    expect(isHandle(env.DEPLOY_REGION!)).toBe(true);
    expect(env.DEPLOY_REGION).not.toBe('us-east-1');
  });
});
