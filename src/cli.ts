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
 * The shape a `--force-scrub NAME` must match: a POSIX env-var name
 * (`[A-Za-z_][A-Za-z0-9_]*`). Validated at parse time so a NAME can never
 * contain the comma the `CHAFF_FORCE_SCRUB` channel joins on — that keeps the
 * launcher join (`src/launcher.ts`) + exec split (`parseForceScrubEnv`,
 * `src/exec.ts`) round-trip unambiguous, so a NAME like `FOO,BAR` is rejected
 * here rather than silently splitting into two entries downstream (DAR-1151).
 */
const ENV_VAR_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Extract every repeatable `--force-scrub NAME` option from `args`, returning
 * the collected names plus the remaining args. A trailing `--force-scrub` with
 * no following NAME throws {@link UsageError}, as does a NAME that is not a valid
 * env-var name ({@link ENV_VAR_NAME}) — the latter keeps the `CHAFF_FORCE_SCRUB`
 * cross-process channel unambiguous (DAR-1151). Only `--force-scrub` is consumed;
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
      if (!ENV_VAR_NAME.test(name)) {
        throw new UsageError(
          `--force-scrub NAME must be a valid env-var name (${ENV_VAR_NAME.source}), got: ${name}`,
        );
      }
      forceScrub.push(name);
      i++;
      continue;
    }
    rest.push(args[i]!);
  }
  return { forceScrub, rest };
}

/** The result of parsing a `chaff run` arg list (DAR-1099). */
export interface RunArgsParse {
  /** Every `--force-scrub NAME` collected from the chaff-option segment, in order. */
  forceScrub: string[];
  /**
   * The harness command (and its args) verbatim — everything after the first
   * `--`, or the leftover option-segment args when no `--` is present. Never
   * scanned for chaff options, so a harness flag named `--force-scrub` is
   * preserved.
   */
  harnessArgs: string[];
}

/**
 * Parse a `chaff run` arg list into its `--force-scrub` overrides and the
 * harness command. `--` terminates chaff option parsing: everything after the
 * first `--` is the harness command verbatim and is NOT scanned for chaff
 * options (so `chaff run --force-scrub A -- tool --force-scrub B` collects only
 * `['A']` and the harness argv stays `['tool', '--force-scrub', 'B']`). When no
 * `--` is present, the whole list is the chaff-option segment and the leftover
 * after extracting `--force-scrub` pairs is the harness command. A trailing
 * `--force-scrub` with no NAME throws {@link UsageError}.
 */
export function parseRunArgs(args: string[]): RunArgsParse {
  const sepIndex = args.indexOf('--');
  if (sepIndex === -1) {
    const { forceScrub, rest } = parseForceScrub(args);
    return { forceScrub, harnessArgs: rest };
  }
  const { forceScrub } = parseForceScrub(args.slice(0, sepIndex));
  return { forceScrub, harnessArgs: args.slice(sepIndex + 1) };
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
