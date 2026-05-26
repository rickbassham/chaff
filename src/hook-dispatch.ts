/**
 * Layer D PreToolUse dispatch (DAR-1107). The pure decision core the thin
 * `bin/chaff-hook.ts` entry calls with its parsed stdin + parsed argv — split
 * from the stdin/stdout I/O the way {@link import('./cli.js')} is split from
 * `src/bin/chaff.ts`, so the routing is unit-testable without spawning a process.
 *
 * Routing (one tool call → one decision):
 *  - `Bash` → {@link import('./hook.js').decideHookOutput} (DAR-1104): base64-wrap
 *    the command, with the idempotency guard. This module does not re-implement
 *    that logic; it delegates.
 *  - `Read`/`Glob`/`Grep` → the injected secret-file decision fn first. If it
 *    returns a decision, that is the output. If it declines (returns `{}`) AND
 *    `--strict-reads` is set, the injected strict-reads fn is consulted next.
 *    A secret-file deny therefore takes priority over the strict-reads leg.
 *  - anything else → no decision (`{}`).
 *
 * Committed ordering (2) per the approved contract: this issue wires the
 * *routing* of Read/Glob/Grep to the secret-file (DAR-1105) and `--strict-reads`
 * (DAR-1106) decision functions. The functions themselves are injected here so
 * the dispatch is gradeable today; their real pattern/deny logic lands in those
 * siblings. The dispatcher never fabricates a deny — it emits only what an
 * injected fn returns.
 */

import { decideHookOutput, type HookOutput, type PreToolUseInput } from './hook.js';

/** The read-family tools whose reads route to the deny / strict-reads legs. */
const READ_TOOLS = new Set(['Read', 'Glob', 'Grep']);

/**
 * The hook output this dispatcher can emit. `hookSpecificOutput` is absent for
 * "no decision". When present it carries either a Bash command rewrite
 * (`updatedInput`, from DAR-1104) or a permission decision
 * (`permissionDecision` + `permissionDecisionReason`, from the secret-file /
 * strict-reads legs) — a single object whose branch-specific fields are
 * optional, mirroring Claude Code's one `hookSpecificOutput` shape. DAR-1104's
 * required-`updatedInput` output is assignable to it.
 */
export interface HookDispatchOutput {
  hookSpecificOutput?: {
    hookEventName: 'PreToolUse';
    updatedInput?: { command: string };
    permissionDecision?: 'allow' | 'deny';
    permissionDecisionReason?: string;
  };
}

/**
 * A read-family decision function. Given a parsed PreToolUse input, it either
 * returns a decision (e.g. a deny) or declines with `{}`. The secret-file
 * (DAR-1105) and `--strict-reads` (DAR-1106) modules implement this shape; here
 * they are injected so the routing is provable with stubs.
 */
export type ReadDecision = (input: PreToolUseInput) => HookDispatchOutput;

/** A read-family decision fn that always declines. The safe default. */
const declineRead: ReadDecision = () => ({});

/** Options controlling dispatch. The injected decision fns default to declining. */
export interface DispatchOptions {
  /** Whether the bin's argv carried `--strict-reads`; gates the strict-reads leg. */
  strictReads: boolean;
  /** The Bash decision fn. Defaults to DAR-1104's {@link decideHookOutput}. */
  decideBash?: (input: PreToolUseInput) => HookOutput;
  /** The secret-file deny decision fn (DAR-1105). Defaults to declining. */
  decideSecretFile?: ReadDecision;
  /** The strict-reads deny decision fn (DAR-1106). Defaults to declining. */
  decideStrictReads?: ReadDecision;
}

/**
 * Decide the PreToolUse hook output for a parsed input, dispatching by tool name
 * (see module doc for the routing rules). Pure: derived solely from the
 * arguments, no I/O.
 */
export function dispatchHook(input: PreToolUseInput, options: DispatchOptions): HookDispatchOutput {
  if (input.tool_name === 'Bash') {
    return (options.decideBash ?? decideHookOutput)(input);
  }

  if (READ_TOOLS.has(input.tool_name)) {
    const decideSecretFile = options.decideSecretFile ?? declineRead;
    const secretFile = decideSecretFile(input);
    if (secretFile.hookSpecificOutput !== undefined) {
      return secretFile;
    }
    if (options.strictReads) {
      const decideStrictReads = options.decideStrictReads ?? declineRead;
      return decideStrictReads(input);
    }
    return {};
  }

  return {};
}
