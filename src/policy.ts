/**
 * Secret classification policy.
 *
 * Decides, for each env var in a snapshot, whether it is a secret (and so
 * should get a handle downstream). The decision uses three mechanisms, in
 * priority order:
 *
 *   1. allowlist — names explicitly declared never-secret (e.g. PATH, HOME)
 *   2. name globs — names matching a secret-shaped pattern (e.g. `*_KEY`)
 *   3. entropy backstop — unrecognized names whose VALUE looks random
 *
 * Anything that none of these flags falls through as a non-secret `default`.
 *
 * This module is a pure function: it reads only its `(envSnapshot, config)`
 * arguments, performs no I/O, and does not consult `process.env`. It answers
 * only "is it a secret" — redaction-eligibility ("safe to global-replace in
 * output") is a separate concern handled elsewhere (see PLAN.md decision #3).
 */

/** A map of env-var name to value, as captured at launch time. */
export type EnvSnapshot = Record<string, string>;

/** Which mechanism decided a var's classification. */
export type Mechanism = 'glob' | 'allowlist' | 'entropy' | 'default';

/** The classification verdict for a single env var. */
export interface VarClassification {
  /** Whether the var is considered a secret. */
  secret: boolean;
  /** The mechanism that produced the verdict, so callers can explain it. */
  mechanism: Mechanism;
}

/** The per-var classification result keyed by env-var name. */
export type Classification = Record<string, VarClassification>;

/** Tunable inputs to the classifier. All fields are optional; sane defaults apply. */
export interface PolicyConfig {
  /** Name globs that mark a matching var as secret. Defaults to {@link DEFAULT_GLOBS}. */
  globs?: string[];
  /** Names that are never secret, beating any glob. Defaults to {@link DEFAULT_ALLOWLIST}. */
  allowlist?: string[];
}

/** Default secret-shaped name globs. */
export const DEFAULT_GLOBS: readonly string[] = ['*_KEY', '*_TOKEN', '*_SECRET', 'DATABASE_URL'];

/** Default never-secret names. */
export const DEFAULT_ALLOWLIST: readonly string[] = ['PATH', 'HOME', 'LANG', 'PWD'];

/**
 * Minimum value length before the entropy backstop is allowed to fire. Short
 * values (flags, ports, env names) cannot accumulate enough characters to be
 * confidently "random", so we never flag them on entropy alone.
 */
const ENTROPY_MIN_LENGTH = 16;

/**
 * Minimum Shannon entropy (bits per character) for the backstop to fire.
 * Ordinary words and identifiers sit well below this; random secrets sit well
 * above it. A sane default, tunable later if needed.
 */
const ENTROPY_MIN_BITS_PER_CHAR = 3.5;

/** Convert a single name glob into an anchored regex. Only `*` is special. */
function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}

/** Shannon entropy of `value` in bits per character (0 for the empty string). */
function bitsPerChar(value: string): number {
  if (value.length === 0) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** Whether `value` looks high-entropy enough to be a secret on its own. */
function looksHighEntropy(value: string): boolean {
  return value.length >= ENTROPY_MIN_LENGTH && bitsPerChar(value) >= ENTROPY_MIN_BITS_PER_CHAR;
}

/**
 * Classify each var in `envSnapshot` as secret or not, using `config` (or the
 * built-in defaults). Pure: derives its result solely from its arguments.
 */
export function classify(envSnapshot: EnvSnapshot, config: PolicyConfig): Classification {
  const allowlist = new Set(config.allowlist ?? DEFAULT_ALLOWLIST);
  const globPatterns = (config.globs ?? DEFAULT_GLOBS).map(globToRegExp);

  const result: Classification = {};
  for (const [name, value] of Object.entries(envSnapshot)) {
    if (allowlist.has(name)) {
      result[name] = { secret: false, mechanism: 'allowlist' };
    } else if (globPatterns.some((re) => re.test(name))) {
      result[name] = { secret: true, mechanism: 'glob' };
    } else if (looksHighEntropy(value)) {
      result[name] = { secret: true, mechanism: 'entropy' };
    } else {
      result[name] = { secret: false, mechanism: 'default' };
    }
  }
  return result;
}
