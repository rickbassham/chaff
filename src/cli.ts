/**
 * CLI argument parsing for the `chaff` binary. Kept separate from the thin bin
 * entry (`src/bin/chaff.ts`) so the dispatch logic is unit-testable.
 */

export const COMMANDS = ['run', 'exec', 'scan', 'audit', 'install-hooks'] as const;

export type Command = (typeof COMMANDS)[number];

export interface Invocation {
  command: Command;
  args: string[];
}

/** Thrown when argv does not name a known command. */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export function isCommand(value: string): value is Command {
  return (COMMANDS as readonly string[]).includes(value);
}

/** Split argv into a command and its remaining args, or throw UsageError. */
export function parseInvocation(argv: string[]): Invocation {
  const [command, ...args] = argv;
  if (command === undefined) {
    throw new UsageError('no command given');
  }
  if (!isCommand(command)) {
    throw new UsageError(`unknown command: ${command}`);
  }
  return { command, args };
}

export const USAGE = `chaff — keep env-var secrets out of LLM histories

Usage: chaff <command> [args]

Commands:
  run            Launch a harness with secret env vars replaced by handles
  exec           Resolve handles, run a command, scrub its output
  scan           Dry-run: show what would be redacted (and gate skips)
  audit          Pretty-print the broker audit log
  install-hooks  Merge chaff's PreToolUse hook into settings.json
`;
