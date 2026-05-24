/**
 * Layer A config loading — user- and folder-level allowlist / managed-secret
 * configuration layered onto the shipped defaults (PLAN.md "Layer A", DAR-1140).
 *
 * Two config levels extend what {@link DEFAULT_PASSTHROUGH_ALLOWLIST} ships:
 *
 *   - **user-level** (`$XDG_CONFIG_HOME/chaff/` → fallback `~/.config/chaff/`):
 *     extra pass-through allowlist entries, explicitly-declared managed secrets,
 *     and a **never-pass** set (user-only) of vars that must never pass through.
 *   - **folder-level** (`./.chaff/` relative to cwd): extra pass-through
 *     allowlist entries and declared managed secrets. It may NOT define a
 *     never-pass set — only the user can block a var.
 *
 * The effective config merges defaults→user→folder with two trust guards:
 *
 *   1. The user never-pass set wins over every allowlist source (defaults, user,
 *      folder) — a checked-in repo `.chaff` cannot force a user-blocked var
 *      through to the model.
 *   2. A folder-level allowlist entry whose value trips the secret heuristics
 *      ({@link classify}) raises a warning naming that var (by NAME only, never
 *      its value) — so a checked-in `.chaff` cannot silently pass a secret. The
 *      guard is folder-scoped: a user-level secret-looking entry is the user's
 *      deliberate choice and does not warn.
 *
 * On-disk format is an implementation detail (JSON here); callers consume the
 * loader's public API ({@link loadUserConfig}, {@link loadFolderConfig},
 * {@link mergeConfig}), never the file contents. The merged effective allowlist
 * + declared-managed set is wired into `runLauncher` → `buildHarnessEnv`
 * (see launcher.ts). The default-deny env construction itself ships in DAR-1139
 * and is consumed unchanged; `chaff scan` reporting under the effective config
 * is DAR-1141.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { classify, type EnvSnapshot } from './policy.js';

/** The basename of the config file within a chaff config directory. */
const CONFIG_FILENAME = 'config.json';

/**
 * A single config level's contributions. `neverPass` is meaningful only at the
 * user level; the folder loader never populates it (only the user may block a
 * var). Arrays default to empty when a level is absent or omits a field.
 */
export interface LevelConfig {
  /** Extra pass-through allowlist entries (literal names or `*`-globs). */
  allowlist: string[];
  /** Names explicitly declared as managed secrets (handled even if not flagged). */
  declaredManaged: string[];
  /** User-only: names that must never pass through, beating every allowlist. */
  neverPass?: string[];
}

/** Inputs to {@link mergeConfig}. */
export interface MergeConfigOptions {
  /** The shipped default passthrough allowlist (literal names and `*`-globs). */
  defaults: readonly string[];
  /** User-level contributions (may carry a never-pass set). */
  user: LevelConfig;
  /** Folder-level contributions (never a never-pass set). */
  folder: LevelConfig;
  /**
   * The env snapshot the folder-trust guard checks folder allowlist entries
   * against: an entry whose value trips the secret heuristics warns.
   */
  snapshot: EnvSnapshot;
}

/** The merged, effective config handed to {@link buildHarnessEnv}. */
export interface EffectiveConfig {
  /**
   * The effective passthrough allowlist: union of defaults, user, and folder
   * allowlists, minus the user never-pass set. Sorted.
   */
  allowlist: string[];
  /** The effective declared-managed set: union of user and folder. Sorted. */
  declaredManaged: string[];
  /**
   * Folder-trust warnings (by NAME, never a value) — one per folder allowlist
   * entry whose value trips the secret heuristics for the given snapshot.
   */
  warnings: string[];
}

/** Read and parse a JSON config file from `dir`, or null when it is absent/unreadable. */
function readConfigFile(dir: string): unknown {
  try {
    const text = readFileSync(join(dir, CONFIG_FILENAME), 'utf8');
    return JSON.parse(text) as unknown;
  } catch {
    // Missing dir/file, unreadable, or malformed JSON: treat as no config. Not
    // crashing on absent config is required (AC-1); rich schema validation is
    // out of scope.
    return null;
  }
}

/** Coerce an unknown JSON field into a string array (empty when absent/wrong-typed). */
function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === 'string');
}

/**
 * Write `config` as JSON into the chaff config directory `dir` (which must
 * already exist). Used by tests to seed config without pinning the on-disk
 * format into assertions; production reads via the loaders below.
 */
export function writeConfig(dir: string, config: Partial<LevelConfig>): void {
  writeFileSync(join(dir, CONFIG_FILENAME), JSON.stringify(config), 'utf8');
}

/**
 * Resolve the user-level config directory: `$XDG_CONFIG_HOME/chaff` when
 * `XDG_CONFIG_HOME` is set and non-empty, else `~/.config/chaff` (from `HOME`).
 */
function userConfigDir(env: EnvSnapshot): string {
  const xdg = env.XDG_CONFIG_HOME;
  if (xdg !== undefined && xdg.length > 0) {
    return join(xdg, 'chaff');
  }
  return join(env.HOME ?? '', '.config', 'chaff');
}

/**
 * Load the user-level config from `$XDG_CONFIG_HOME/chaff` (fallback
 * `~/.config/chaff`). Returns empty contributions when no config is present.
 * The user level is the only one that may define a never-pass set.
 */
export function loadUserConfig(env: EnvSnapshot): LevelConfig {
  const raw = readConfigFile(userConfigDir(env));
  if (raw === null || typeof raw !== 'object') {
    return { allowlist: [], declaredManaged: [] };
  }
  const obj = raw as Record<string, unknown>;
  const config: LevelConfig = {
    allowlist: asStringArray(obj.allowlist),
    declaredManaged: asStringArray(obj.declaredManaged),
  };
  const neverPass = asStringArray(obj.neverPass);
  if (neverPass.length > 0) {
    config.neverPass = neverPass;
  }
  return config;
}

/**
 * Load the folder-level config from `./.chaff` relative to `cwd`. Returns empty
 * contributions when no config is present. A folder config can never define a
 * never-pass set (only the user may block a var), so any `neverPass` field in
 * the file is ignored.
 */
export function loadFolderConfig(cwd: string): LevelConfig {
  const raw = readConfigFile(join(cwd, '.chaff'));
  if (raw === null || typeof raw !== 'object') {
    return { allowlist: [], declaredManaged: [] };
  }
  const obj = raw as Record<string, unknown>;
  return {
    allowlist: asStringArray(obj.allowlist),
    declaredManaged: asStringArray(obj.declaredManaged),
  };
}

/**
 * Merge defaults→user→folder into the effective config. The effective allowlist
 * is the union of all three allowlist sources minus the user never-pass set
 * (which beats every source, including the shipped defaults). The declared-
 * managed set is the union of user and folder. Folder allowlist entries whose
 * value trips the secret heuristics raise a NAME-only warning (the folder-trust
 * guard); user-level entries do not (the guard is folder-scoped).
 */
export function mergeConfig(options: MergeConfigOptions): EffectiveConfig {
  const { defaults, user, folder, snapshot } = options;
  const neverPass = new Set(user.neverPass ?? []);

  const allowlist = [...defaults, ...user.allowlist, ...folder.allowlist].filter(
    (name) => !neverPass.has(name),
  );
  const declaredManaged = [...user.declaredManaged, ...folder.declaredManaged];

  // Folder-trust guard: warn for any folder-allowlisted var whose value trips
  // the secret heuristics for the current snapshot. classify() is the same
  // advisory detector the launcher uses; here it gates the warning only — the
  // value is never included in the message.
  const classification = classify(snapshot, {});
  const warnings: string[] = [];
  for (const name of folder.allowlist) {
    if (classification[name]?.secret === true) {
      warnings.push(
        `${name} is allowlisted by a folder-level .chaff config but its value looks like a secret — review before trusting this repo config`,
      );
    }
  }

  return {
    allowlist: dedupeSorted(allowlist),
    declaredManaged: dedupeSorted(declaredManaged),
    warnings,
  };
}

/** Deduplicate and sort a list of names for a stable effective set. */
function dedupeSorted(names: string[]): string[] {
  return [...new Set(names)].sort();
}

/** Inputs to {@link loadEffectiveConfig}. */
export interface LoadEffectiveConfigOptions {
  /** The shipped default passthrough allowlist. */
  defaults: readonly string[];
  /** Env used to resolve config locations (XDG_CONFIG_HOME / HOME). */
  configEnv: EnvSnapshot;
  /** Working directory whose `./.chaff` is the folder-level config. */
  cwd: string;
  /** The launch env snapshot the folder-trust guard checks against. */
  snapshot: EnvSnapshot;
}

/**
 * Discover the user- and folder-level config from disk and merge them onto the
 * shipped defaults, returning the effective config the launcher hands to
 * {@link buildHarnessEnv}. Convenience over calling {@link loadUserConfig},
 * {@link loadFolderConfig}, and {@link mergeConfig} in sequence.
 */
export function loadEffectiveConfig(options: LoadEffectiveConfigOptions): EffectiveConfig {
  return mergeConfig({
    defaults: options.defaults,
    user: loadUserConfig(options.configEnv),
    folder: loadFolderConfig(options.cwd),
    snapshot: options.snapshot,
  });
}
