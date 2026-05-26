/**
 * `chaff install-hooks` (DAR-1107): idempotently merge chaff's PreToolUse hook
 * into a Claude Code `settings.json`, preserving every existing hook and
 * top-level key.
 *
 * The hook entry registers {@link CHAFF_HOOK_COMMAND} as a `PreToolUse` command
 * hook matching the tools chaff acts on: `Bash` (base64-wrap, DAR-1104) plus the
 * read-family `Read`/`Glob`/`Grep` (secret-file deny / `--strict-reads` routing,
 * DAR-1105/1106). Per the permission-passthrough spike on DAR-1107, no separate
 * Bash *allow* rule is added — the hook's own rewrite is authorized on its own.
 *
 * Idempotency: chaff's entry is identified by its command string. A re-run that
 * finds an existing PreToolUse entry invoking {@link CHAFF_HOOK_COMMAND} makes no
 * change, so the serialized file is byte-identical on the second run. Unknown
 * hooks and other settings keys are passed through untouched.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

/** The command Claude Code invokes for chaff's PreToolUse hook. */
export const CHAFF_HOOK_COMMAND = 'chaff-hook';

/** The tools chaff's hook matches: Bash (wrap) + the read family (deny routing). */
export const CHAFF_HOOK_MATCHER = 'Bash|Read|Glob|Grep';

/** A single command hook within a matcher group. */
interface CommandHook {
  type: 'command';
  command: string;
}

/** A PreToolUse matcher group: a matcher plus its command hooks. */
interface MatcherGroup {
  matcher?: string;
  hooks?: CommandHook[];
}

/** The settings.json shape this installer reads/writes (open: other keys pass through). */
interface Settings {
  hooks?: { PreToolUse?: MatcherGroup[]; [event: string]: MatcherGroup[] | undefined };
  [key: string]: unknown;
}

/** chaff's PreToolUse matcher group. */
function chaffGroup(): MatcherGroup {
  return {
    matcher: CHAFF_HOOK_MATCHER,
    hooks: [{ type: 'command', command: CHAFF_HOOK_COMMAND }],
  };
}

/** Does any command hook in `groups` already invoke chaff's hook command? */
function hasChaffHook(groups: MatcherGroup[]): boolean {
  return groups.some((group) =>
    (group.hooks ?? []).some((hook) => hook.command === CHAFF_HOOK_COMMAND),
  );
}

/**
 * Merge chaff's PreToolUse hook into `settings`, returning the merged object.
 * Pure with respect to the input (the input is not mutated). When chaff's hook
 * is already present, returns an equivalent object so re-serialization is stable.
 */
export function mergeChaffHook(settings: Settings): Settings {
  const existingHooks = settings.hooks ?? {};
  const existingPreToolUse = existingHooks.PreToolUse ?? [];

  const preToolUse = hasChaffHook(existingPreToolUse)
    ? existingPreToolUse
    : [...existingPreToolUse, chaffGroup()];

  return {
    ...settings,
    hooks: { ...existingHooks, PreToolUse: preToolUse },
  };
}

/**
 * The default settings.json the CLI merges into when no path is given:
 * Claude Code's user settings at `~/.claude/settings.json`. Tests pass an
 * explicit path instead.
 */
export function defaultSettingsPath(): string {
  return join(homedir(), '.claude', 'settings.json');
}

export interface InstallHooksOptions {
  /** Path to the settings.json to merge into (created if absent). */
  settingsPath: string;
}

/**
 * Read `settingsPath` (treating a missing file as empty settings), merge chaff's
 * PreToolUse hook, and write it back as pretty-printed JSON. Creates parent
 * directories as needed. Idempotent: a second run writes a byte-identical file.
 */
export function runInstallHooks(options: InstallHooksOptions): number {
  let settings: Settings = {};
  try {
    settings = JSON.parse(readFileSync(options.settingsPath, 'utf8')) as Settings;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err;
    }
  }

  const merged = mergeChaffHook(settings);

  mkdirSync(dirname(options.settingsPath), { recursive: true });
  writeFileSync(options.settingsPath, `${JSON.stringify(merged, null, 2)}\n`);
  return 0;
}
