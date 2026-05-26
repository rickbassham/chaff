/**
 * Layer D PreToolUse command-wrapping logic (PLAN.md "Layer D", decision #2).
 *
 * Claude Code's `PreToolUse` hook can rewrite a Bash tool call's command before
 * the harness runs it, via `hookSpecificOutput.updatedInput.command`. This module
 * is the pure decision function: given a parsed PreToolUse input, it base64-wraps
 * a Bash command into `chaff exec --b64 '<blob>'` so the consumer in
 * `src/exec.ts` ({@link import('./exec.js').decodeCommand}) can decode and run it
 * with the real secret values resolved into the inner shell's env.
 *
 * Why base64 (decision #2): the harness re-parses `updatedInput.command` through
 * a shell before chaff sees it. Wrapping the original command as a base64 blob
 * defers BOTH shell-parsing AND `$VAR` expansion to the inner shell `chaff exec`
 * spawns — which has the real values — instead of the harness shell, which holds
 * only handles. `Buffer.from(cmd).toString('base64')` is single-line (no 76-col
 * wrapping) and draws only from `[A-Za-z0-9+/=]`, so it is a single safe token;
 * it is single-quoted anyway as insurance against future alphabet changes.
 *
 * Idempotency (decision #2): if a command already starts with the
 * {@link WRAPPER_PREFIX}, it is passed through unchanged so re-running the hook
 * over an already-wrapped command never double-wraps or recurses.
 *
 * This module is a pure, deterministic leaf: no stdin/stdout, no environment
 * reads, no subprocess spawning. The thin `bin/chaff-hook.ts` entry that reads the hook JSON
 * from stdin and writes the result to stdout is a separate concern (DAR-1107), as
 * are the secret-file deny-list (DAR-1105) and `--strict-reads` (DAR-1106).
 */

/** The Bash tool's name in the PreToolUse payload. Only this tool is wrapped. */
const BASH_TOOL_NAME = 'Bash';

/**
 * The wrapper prefix. A command already starting with this is treated as
 * already-wrapped (idempotency guard) and passed through unchanged. The trailing
 * space matters: it is the boundary before the single-quoted blob.
 */
const WRAPPER_PREFIX = 'chaff exec --b64 ';

/** The parsed input chaff receives for a PreToolUse hook event. */
export interface PreToolUseInput {
  hook_event_name: string;
  tool_name: string;
  tool_input: { command?: string; [key: string]: unknown };
}

/** The hook output: a command rewrite under `hookSpecificOutput`, or nothing. */
export interface HookOutput {
  hookSpecificOutput?: {
    hookEventName: 'PreToolUse';
    updatedInput: { command: string };
  };
}

/** base64-wrap a command into the `chaff exec --b64 '<blob>'` token. */
function wrap(command: string): string {
  const blob = Buffer.from(command, 'utf8').toString('base64');
  return `${WRAPPER_PREFIX}'${blob}'`;
}

/**
 * Decide the PreToolUse hook output for a parsed input.
 *
 * For a Bash tool call, returns a `hookSpecificOutput.updatedInput.command`
 * rewrite that base64-wraps the original command — unless the command is already
 * wrapped (starts with {@link WRAPPER_PREFIX}), in which case it passes through.
 * Any non-Bash tool call passes through with no rewrite. The result is derived
 * solely from the argument (pure and deterministic).
 */
export function decideHookOutput(input: PreToolUseInput): HookOutput {
  if (input.tool_name !== BASH_TOOL_NAME) {
    return {};
  }
  const command = input.tool_input.command;
  if (command === undefined || command.startsWith(WRAPPER_PREFIX)) {
    return {};
  }
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      updatedInput: { command: wrap(command) },
    },
  };
}
