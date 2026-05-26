/**
 * Layer D secret-file deny-list (PLAN.md "Layer D", decision #4 partial
 * mitigation; DAR-1105).
 *
 * Claude Code's `PreToolUse` hook can deny a tool call by returning
 * `hookSpecificOutput.permissionDecision: "deny"` with a
 * `permissionDecisionReason`. This module is the pure decision function for the
 * read-family tools (`Read`/`Glob`/`Grep`): if the call targets a path whose
 * basename matches a well-known secret-file name pattern, it denies; otherwise
 * it declines (returns exactly `{}`) so the dispatcher lets the read proceed.
 *
 * Routing/wiring lives in {@link import('./hook-dispatch.js').dispatchHook},
 * which injects this function via its `decideSecretFile` slot. This module only
 * decides; it never reads I/O.
 *
 * Name patterns (the fixed AC set): `.env*`, `*.pem`, `id_*`, `*.key`,
 * `credentials*`. Matching is on the target's **basename**, so the leading
 * directory never defeats (or triggers) a match. The `*` is anchored to a
 * segment boundary rather than treated as a raw glob: a prefix pattern matches
 * when the basename equals the prefix, the prefix already ends in a separator
 * (`id_` → `id_rsa`), or the character after the prefix is a non-alphanumeric
 * separator (`.env` → `.env.local`). This is why `credentials.json` matches but
 * `credentialsHelper.ts` does not, and `.env.local` matches but `environment.ts`
 * does not — pinning the false-positive boundary instead of over-denying every
 * file that merely starts with the prefix word.
 *
 * Partial mitigation (decision #4): this is name-pattern deny only. The general
 * disk write→read-back gap (a secret written to an arbitrary filename and read
 * back) is the #1 residual gap, addressed partially by `--strict-reads` + the
 * working-tree scan (DAR-1106) and documented in the README (DAR-1108).
 *
 * This module is a pure, deterministic leaf: no stdin/stdout, no environment
 * reads, no subprocess spawning, no filesystem access.
 */

import type { PreToolUseInput } from './hook.js';
import type { HookDispatchOutput } from './hook-dispatch.js';

/** A secret-file name pattern. Either a prefix (`.env*`) or a suffix (`*.pem`). */
type NamePattern = { kind: 'prefix'; literal: string } | { kind: 'suffix'; literal: string };

/** The fixed AC deny-list: `.env*`, `*.pem`, `id_*`, `*.key`, `credentials*`. */
const PATTERNS: readonly NamePattern[] = [
  { kind: 'prefix', literal: '.env' },
  { kind: 'suffix', literal: '.pem' },
  { kind: 'prefix', literal: 'id_' },
  { kind: 'suffix', literal: '.key' },
  { kind: 'prefix', literal: 'credentials' },
];

/** True when `ch` is a non-alphanumeric segment separator (or absent). */
function isSeparator(ch: string | undefined): boolean {
  return ch !== undefined && !/[A-Za-z0-9]/.test(ch);
}

/**
 * The basename of a path, splitting on both `/` and `\` so the match is
 * platform-neutral and unaffected by the leading directory.
 */
function basename(path: string): string {
  const segments = path.split(/[/\\]/);
  return segments[segments.length - 1] ?? path;
}

/** True when `name` matches the segment-anchored pattern (see module doc). */
function matchesPattern(name: string, pattern: NamePattern): boolean {
  if (pattern.kind === 'suffix') {
    return name.endsWith(pattern.literal);
  }
  if (!name.startsWith(pattern.literal)) {
    return false;
  }
  const rest = name.slice(pattern.literal.length);
  if (rest === '') {
    return true;
  }
  return isSeparator(pattern.literal[pattern.literal.length - 1]) || isSeparator(rest[0]);
}

/**
 * The target path of a read-family tool call. `Read` uses `file_path`, `Glob`
 * uses `pattern`, and `Grep` uses `pattern` (and optionally `path`). We check
 * every candidate so a secret name in any of them is caught.
 */
function targetPaths(input: PreToolUseInput): string[] {
  const candidates = ['file_path', 'pattern', 'path'];
  const paths: string[] = [];
  for (const key of candidates) {
    const value = input.tool_input[key];
    if (typeof value === 'string') {
      paths.push(value);
    }
  }
  return paths;
}

/**
 * Decide the PreToolUse hook output for a read-family tool call. Denies with a
 * reason when any target path's basename matches a secret-file name pattern;
 * otherwise declines (`{}`). Pure and deterministic — derived solely from the
 * argument.
 */
export function decideSecretFile(input: PreToolUseInput): HookDispatchOutput {
  for (const path of targetPaths(input)) {
    const name = basename(path);
    const matched = PATTERNS.find((pattern) => matchesPattern(name, pattern));
    if (matched !== undefined) {
      return {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: `chaff: reading "${name}" is denied — it matches a secret-file name pattern (.env*, *.pem, id_*, *.key, credentials*). Secrets must stay out of the transcript; use \`chaff exec\` so values are resolved in a subprocess and scrubbed on egress.`,
        },
      };
    }
  }
  return {};
}
