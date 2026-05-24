/**
 * DAR-1140 — user + folder config loading, defaults→user→folder merge, and the
 * folder-trust guard.
 *
 * Exercises the config-loader's public API (not its on-disk format, which is an
 * implementation choice per the issue scope):
 *   - discovery of user-level config ($XDG_CONFIG_HOME/chaff → ~/.config/chaff)
 *     and folder-level config (./.chaff),
 *   - the defaults→user→folder merge that yields the effective allowlist and
 *     declared-managed set,
 *   - the never-pass set (user-only) that no folder entry can override,
 *   - the folder-trust guard: a folder allowlist entry whose value trips the
 *     secret heuristics warns (by NAME only, never the value); a user-level
 *     secret-looking entry does not (the guard is folder-scoped).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadUserConfig,
  loadFolderConfig,
  mergeConfig,
  writeConfig,
  type LevelConfig,
} from '../src/config.js';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-cfg-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

/** Create a chaff config dir under `parent` and write `config` into it. */
function seedConfigDir(parent: string, config: Partial<LevelConfig>): string {
  const dir = join(parent, 'chaff');
  mkdirSync(dir, { recursive: true });
  writeConfig(dir, config);
  return dir;
}

describe('ac-1: user- and folder-level config discovery', () => {
  it('user-level config is discovered at $XDG_CONFIG_HOME/chaff when XDG_CONFIG_HOME is set, and its allowlist + declared-managed entries appear in the loaded result', () => {
    const xdg = join(tmp, 'xdg');
    seedConfigDir(xdg, {
      allowlist: ['MY_PASS_VAR'],
      declaredManaged: ['MY_MANAGED_VAR'],
    });

    const loaded = loadUserConfig({ XDG_CONFIG_HOME: xdg, HOME: join(tmp, 'home') });
    expect(loaded.allowlist).toContain('MY_PASS_VAR');
    expect(loaded.declaredManaged).toContain('MY_MANAGED_VAR');
  });

  it('with XDG_CONFIG_HOME unset, user-level config falls back to ~/.config/chaff and is loaded from there', () => {
    const home = join(tmp, 'home');
    seedConfigDir(join(home, '.config'), {
      allowlist: ['HOME_PASS_VAR'],
      declaredManaged: ['HOME_MANAGED_VAR'],
    });

    const loaded = loadUserConfig({ HOME: home });
    expect(loaded.allowlist).toContain('HOME_PASS_VAR');
    expect(loaded.declaredManaged).toContain('HOME_MANAGED_VAR');
  });

  it('folder-level config is discovered at ./.chaff relative to cwd and its allowlist + declared-managed entries appear in the loaded result', () => {
    const cwd = join(tmp, 'repo');
    const dir = join(cwd, '.chaff');
    mkdirSync(dir, { recursive: true });
    writeConfig(dir, {
      allowlist: ['REPO_PASS_VAR'],
      declaredManaged: ['REPO_MANAGED_VAR'],
    });

    const loaded = loadFolderConfig(cwd);
    expect(loaded.allowlist).toContain('REPO_PASS_VAR');
    expect(loaded.declaredManaged).toContain('REPO_MANAGED_VAR');
  });

  it('a user-level never-pass set is parsed and exposed in the loaded result; folder config has no never-pass field (only user-level may define it)', () => {
    const xdg = join(tmp, 'xdg');
    seedConfigDir(xdg, {
      allowlist: ['MY_PASS_VAR'],
      neverPass: ['BLOCKED_VAR'],
    });
    const user = loadUserConfig({ XDG_CONFIG_HOME: xdg, HOME: join(tmp, 'home') });
    expect(user.neverPass).toContain('BLOCKED_VAR');

    const cwd = join(tmp, 'repo');
    const dir = join(cwd, '.chaff');
    mkdirSync(dir, { recursive: true });
    // Even if a folder config file tries to declare neverPass, the folder loader
    // does not expose it (only user-level may define the never-pass set).
    writeConfig(dir, { allowlist: ['REPO_PASS_VAR'], neverPass: ['REPO_TRIES_TO_BLOCK'] });
    const folder = loadFolderConfig(cwd);
    expect(folder.neverPass).toBeUndefined();
  });

  it('a missing config directory at either level yields empty contributions (no throw), so chaff works with no config files present', () => {
    const home = join(tmp, 'nonexistent-home');
    const cwd = join(tmp, 'nonexistent-repo');

    const user = loadUserConfig({ HOME: home });
    expect(user.allowlist).toEqual([]);
    expect(user.declaredManaged).toEqual([]);
    expect(user.neverPass).toBeUndefined();

    const folder = loadFolderConfig(cwd);
    expect(folder.allowlist).toEqual([]);
    expect(folder.declaredManaged).toEqual([]);
  });
});

describe('ac-2: defaults→user→folder merge', () => {
  const DEFAULTS = ['PATH', 'HOME'] as const;

  it('the effective allowlist is the union of shipped defaults, user allowlist, and folder allowlist (an entry contributed only by folder is present; a shipped-default entry is still present)', () => {
    const effective = mergeConfig({
      defaults: DEFAULTS,
      user: { allowlist: ['USER_VAR'], declaredManaged: [] },
      folder: { allowlist: ['FOLDER_VAR'], declaredManaged: [] },
      snapshot: {},
    });
    expect(effective.allowlist).toContain('PATH');
    expect(effective.allowlist).toContain('USER_VAR');
    expect(effective.allowlist).toContain('FOLDER_VAR');
  });

  it('declared-managed is the union of user and folder declared-managed sets', () => {
    const effective = mergeConfig({
      defaults: DEFAULTS,
      user: { allowlist: [], declaredManaged: ['USER_MANAGED'] },
      folder: { allowlist: [], declaredManaged: ['FOLDER_MANAGED'] },
      snapshot: {},
    });
    expect(effective.declaredManaged).toContain('USER_MANAGED');
    expect(effective.declaredManaged).toContain('FOLDER_MANAGED');
  });

  it('a var named in the user never-pass set is excluded from the effective allowlist even when the folder config allowlists it (folder cannot force a user-blocked var through)', () => {
    const effective = mergeConfig({
      defaults: DEFAULTS,
      user: { allowlist: [], declaredManaged: [], neverPass: ['BLOCKED'] },
      folder: { allowlist: ['BLOCKED'], declaredManaged: [] },
      snapshot: {},
    });
    expect(effective.allowlist).not.toContain('BLOCKED');
  });

  it('a var named in the user never-pass set is excluded from the effective allowlist even when it is a shipped default (user never-pass beats defaults)', () => {
    const effective = mergeConfig({
      defaults: ['PATH', 'HOME'],
      user: { allowlist: [], declaredManaged: [], neverPass: ['HOME'] },
      folder: { allowlist: [], declaredManaged: [] },
      snapshot: {},
    });
    expect(effective.allowlist).not.toContain('HOME');
    expect(effective.allowlist).toContain('PATH');
  });
});

describe('ac-3: folder-trust guard', () => {
  it('loading a folder config whose allowlist entry names a var that the secret heuristics flag (for the current snapshot) produces a warning naming that var', () => {
    // OPENAI_API_KEY matches the *_KEY glob → heuristics flag it.
    const effective = mergeConfig({
      defaults: [],
      user: { allowlist: [], declaredManaged: [] },
      folder: { allowlist: ['OPENAI_API_KEY'], declaredManaged: [] },
      snapshot: { OPENAI_API_KEY: 'sk-real-openai-value-123' },
    });
    expect(effective.warnings.join('\n')).toContain('OPENAI_API_KEY');
  });

  it('the folder-trust warning names the var only and never includes its value', () => {
    const effective = mergeConfig({
      defaults: [],
      user: { allowlist: [], declaredManaged: [] },
      folder: { allowlist: ['OPENAI_API_KEY'], declaredManaged: [] },
      snapshot: { OPENAI_API_KEY: 'sk-real-openai-value-123' },
    });
    const joined = effective.warnings.join('\n');
    expect(joined).toContain('OPENAI_API_KEY');
    expect(joined).not.toContain('sk-real-openai-value-123');
  });

  it('a folder allowlist entry naming a var that the heuristics do NOT flag produces no folder-trust warning', () => {
    const effective = mergeConfig({
      defaults: [],
      user: { allowlist: [], declaredManaged: [] },
      folder: { allowlist: ['BUILD_MODE'], declaredManaged: [] },
      snapshot: { BUILD_MODE: 'release' },
    });
    expect(effective.warnings.join('\n')).not.toContain('BUILD_MODE');
  });

  it('a secret-looking var allowlisted by USER-level config (not folder) does not trigger the folder-trust warning (the guard is folder-scoped)', () => {
    const effective = mergeConfig({
      defaults: [],
      user: { allowlist: ['OPENAI_API_KEY'], declaredManaged: [] },
      folder: { allowlist: [], declaredManaged: [] },
      snapshot: { OPENAI_API_KEY: 'sk-real-openai-value-123' },
    });
    expect(effective.warnings.join('\n')).not.toContain('OPENAI_API_KEY');
  });
});

describe('ac-5: precedence and folder-trust restatements (unit)', () => {
  it('precedence: a fixture with distinct entries at the defaults, user, and folder levels produces an effective allowlist equal to their union in the documented merge order', () => {
    const effective = mergeConfig({
      defaults: ['DEFAULT_ONLY'],
      user: { allowlist: ['USER_ONLY'], declaredManaged: [] },
      folder: { allowlist: ['FOLDER_ONLY'], declaredManaged: [] },
      snapshot: {},
    });
    expect([...effective.allowlist].sort()).toEqual(['DEFAULT_ONLY', 'FOLDER_ONLY', 'USER_ONLY']);
  });

  it('a secret-looking folder allowlist entry warns: loading the folder config emits a warning naming that var (value never printed)', () => {
    const effective = mergeConfig({
      defaults: [],
      user: { allowlist: [], declaredManaged: [] },
      folder: { allowlist: ['SERVICE_TOKEN'], declaredManaged: [] },
      snapshot: { SERVICE_TOKEN: 'real-token-value-789' },
    });
    const joined = effective.warnings.join('\n');
    expect(joined).toContain('SERVICE_TOKEN');
    expect(joined).not.toContain('real-token-value-789');
  });
});
