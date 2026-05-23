#!/usr/bin/env node
import { parseInvocation, UsageError, USAGE } from '../cli.js';

function main(argv: string[]): number {
  let invocation;
  try {
    invocation = parseInvocation(argv);
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`chaff: ${err.message}\n\n${USAGE}`);
      return 2;
    }
    throw err;
  }

  // Phase 0 scaffold: the commands are wired but not implemented. Each lands in
  // its phase (see PLAN.md "Build order"). Until then, fail loudly rather than
  // pretend success.
  process.stderr.write(
    `chaff ${invocation.command}: not implemented yet (scaffold). See PLAN.md build order.\n`,
  );
  return 1;
}

process.exitCode = main(process.argv.slice(2));
