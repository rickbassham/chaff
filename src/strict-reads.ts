/**
 * Layer D `--strict-reads` opt-in deny (PLAN.md "Layer D", decision #4 partial
 * mitigation; DAR-1106).
 *
 * The #1 residual gap is a child writing a secret to a file that is then read
 * back through a non-Bash tool (`Read`/`Glob`/`Grep`), bypassing the egress
 * scrubber that only sees `chaff exec` output. `--strict-reads` closes that read
 * leg by denying the read-family tools outright and steering the LLM to read via
 * Bash `cat`/`grep` instead — which the PreToolUse hook rewrites into
 * `chaff exec` (DAR-1104), so the content flows through the scrubber.
 *
 * This is **off by default**: a blanket deny of `Read`/`Glob`/`Grep` loses
 * `Read`'s line-numbers/chunking/image handling, so it is only worth it when the
 * operator opts in. It also only "closes" the leg under a cooperative-LLM threat
 * model: a cooperative LLM, told to use Bash, routes through the scrubber; this
 * is a steer, not a hard guarantee against an adversarial model.
 *
 * Routing/wiring lives in {@link import('./hook-dispatch.js').dispatchHook},
 * which consults this function via its `decideStrictReads` slot ONLY when
 * `--strict-reads` is set AND the secret-file deny (DAR-1105) declined — so a
 * secret-file deny always takes priority over this blanket steer. This module
 * only decides; it never reads I/O.
 *
 * This module is a pure, deterministic leaf: no stdin/stdout, no environment
 * reads, no subprocess spawning, no filesystem access.
 */

import type { HookDispatchOutput } from './hook-dispatch.js';

/**
 * The steer-to-Bash deny reason. Names a Bash read path (`cat`/`grep`) and the
 * `chaff exec` routing so the LLM is told to route reads through the scrubber
 * rather than the denied native tool.
 */
const STRICT_READS_REASON =
  'chaff: native Read/Glob/Grep are disabled under --strict-reads — they bypass the egress ' +
  'scrubber. Read the file via Bash instead (e.g. `cat <path>` or `grep <pattern> <path>`); ' +
  'the Bash tool call is routed through `chaff exec` so any secret in the output is scrubbed.';

/**
 * Decide the PreToolUse hook output for a read-family tool call under
 * `--strict-reads`: always denies with the {@link STRICT_READS_REASON}
 * steer-to-Bash reason. The dispatcher only invokes this for `Read`/`Glob`/`Grep`
 * (and only after the secret-file deny declined), so this function does not
 * re-check the tool name and ignores the input entirely — the deny is the same
 * for any read-family target. It is shaped to satisfy the dispatcher's
 * {@link import('./hook-dispatch.js').ReadDecision} slot (which passes the input)
 * while taking no parameter, since the decision does not depend on it. Pure and
 * deterministic.
 */
export function decideStrictReads(): HookDispatchOutput {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: STRICT_READS_REASON,
    },
  };
}
