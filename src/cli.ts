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

/** The result of pulling `--force-scrub NAME` options out of an arg list. */
export interface ForceScrubParse {
  /**
   * Every NAME passed via a `--force-scrub NAME` option, in order. These flow
   * into redaction-set construction to override the eligibility gate per named
   * secret (DAR-1099, PLAN.md decision #3).
   */
  forceScrub: string[];
  /** The remaining args with every `--force-scrub NAME` pair removed. */
  rest: string[];
}

/**
 * Extract every repeatable `--force-scrub NAME` option from `args`, returning
 * the collected names plus the remaining args. A trailing `--force-scrub` with
 * no following NAME throws {@link UsageError}. Only `--force-scrub` is consumed;
 * all other args (including a `--` separator) are passed through in `rest`.
 */
export function parseForceScrub(args: string[]): ForceScrubParse {
  const forceScrub: string[] = [];
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--force-scrub') {
      const name = args[i + 1];
      if (name === undefined) {
        throw new UsageError('--force-scrub requires a NAME');
      }
      forceScrub.push(name);
      i++;
      continue;
    }
    rest.push(args[i]!);
  }
  return { forceScrub, rest };
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

Options:
  --force-scrub NAME   Push-scrub NAME even if it fails the redaction-eligibility
                       gate (repeatable; accepts possible output corruption)
`;
