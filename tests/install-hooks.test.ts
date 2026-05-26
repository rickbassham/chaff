import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInstallHooks, CHAFF_HOOK_COMMAND } from '../src/install-hooks.js';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cht-install-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

/** Parse a settings.json file at `path`. */
function readSettings(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
}

/** Every `command` string under every PreToolUse hook entry in the settings. */
function preToolUseCommands(settings: Record<string, unknown>): string[] {
  const hooks = settings.hooks as { PreToolUse?: Array<{ hooks?: Array<{ command?: string }> }> };
  const entries = hooks?.PreToolUse ?? [];
  return entries.flatMap((entry) => (entry.hooks ?? []).map((h) => h.command ?? ''));
}

describe('install-hooks — adds chaff PreToolUse hook (ac-2)', () => {
  it('against a settings.json with no `hooks` key, writes valid JSON containing a PreToolUse hook entry invoking the chaff-hook command', () => {
    const path = join(tmp, 'settings.json');
    writeFileSync(path, JSON.stringify({ model: 'sonnet' }, null, 2));

    runInstallHooks({ settingsPath: path });

    const settings = readSettings(path);
    expect(preToolUseCommands(settings)).toContain(CHAFF_HOOK_COMMAND);
  });

  it('against a directory with no existing settings.json, creates the file and any parent dirs, containing chaff PreToolUse hook as valid JSON', () => {
    const path = join(tmp, 'nested', 'dir', 'settings.json');
    expect(existsSync(path)).toBe(false);

    runInstallHooks({ settingsPath: path });

    expect(existsSync(path)).toBe(true);
    const settings = readSettings(path);
    expect(preToolUseCommands(settings)).toContain(CHAFF_HOOK_COMMAND);
  });
});

describe('install-hooks — preserves existing config without clobbering (ac-2)', () => {
  it('an unrelated PreToolUse hook and an unrelated top-level key both survive, with chaff added alongside', () => {
    const path = join(tmp, 'settings.json');
    writeFileSync(
      path,
      JSON.stringify(
        {
          permissions: { allow: ['Bash(ls:*)'] },
          hooks: {
            PreToolUse: [
              { matcher: 'Write', hooks: [{ type: 'command', command: 'other-hook --flag' }] },
            ],
          },
        },
        null,
        2,
      ),
    );

    runInstallHooks({ settingsPath: path });

    const settings = readSettings(path);
    const commands = preToolUseCommands(settings);
    expect(commands).toContain('other-hook --flag');
    expect(commands).toContain(CHAFF_HOOK_COMMAND);
    expect(settings.permissions).toEqual({ allow: ['Bash(ls:*)'] });
  });

  it('other top-level settings keys are byte-for-byte unchanged in value after the merge', () => {
    const path = join(tmp, 'settings.json');
    const permissions = { allow: ['Bash(npm run test:*)'], deny: ['Read(./.env)'] };
    writeFileSync(path, JSON.stringify({ model: 'opus', permissions }, null, 2));

    runInstallHooks({ settingsPath: path });

    const settings = readSettings(path);
    expect(settings.model).toBe('opus');
    expect(settings.permissions).toEqual(permissions);
  });
});

describe('install-hooks — idempotent re-run (ac-2)', () => {
  it('running twice produces byte-identical settings.json the second time; chaff hook appears exactly once', () => {
    const path = join(tmp, 'settings.json');
    writeFileSync(
      path,
      JSON.stringify(
        {
          hooks: {
            PreToolUse: [{ matcher: 'Write', hooks: [{ type: 'command', command: 'other-hook' }] }],
          },
        },
        null,
        2,
      ),
    );

    runInstallHooks({ settingsPath: path });
    const afterFirst = readFileSync(path, 'utf8');
    runInstallHooks({ settingsPath: path });
    const afterSecond = readFileSync(path, 'utf8');

    expect(afterSecond).toBe(afterFirst);
    const commands = preToolUseCommands(readSettings(path));
    expect(commands.filter((c) => c === CHAFF_HOOK_COMMAND)).toHaveLength(1);
  });
});
