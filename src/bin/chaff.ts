#!/usr/bin/env node
import { parseInvocation, UsageError, USAGE } from '../cli.js';
import { runLauncher, defaultAuditLogPath } from '../launcher.js';
import { runScan } from '../scan.js';
import { runExec } from '../exec.js';

/**
 * Dispatch one invocation. Returns a number for synchronous commands or a
 * promise resolving to one for `chaff run` (which awaits the harness). The
 * remaining commands are still Phase 0 scaffolds (see PLAN.md build order).
 */
function main(argv: string[]): number | Promise<number> {
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

  if (invocation.command === 'run') {
    // `chaff run -- <harness cmd>`: drop the leading `--` separator if present.
    const args = invocation.args[0] === '--' ? invocation.args.slice(1) : invocation.args;
    if (args.length === 0) {
      process.stderr.write('chaff run: no harness command given after --\n\n' + USAGE);
      return 2;
    }
    return runLauncher({ argv: args, auditLogPath: defaultAuditLogPath() });
  }

  if (invocation.command === 'scan') {
    // `chaff scan`: classification dry-run. Reads process.env, prints the
    // report to stdout, starts no broker, and spawns nothing.
    return runScan();
  }

  if (invocation.command === 'exec') {
    // `chaff exec --b64 <blob>`: base64-decode the wrapped command, resolve
    // handle-valued env vars into the child env via CHAFF_SOCK, and run the
    // decoded command under the inner shell (PLAN.md decision #2).
    return runExec({ args: invocation.args });
  }

  // Phase 0 scaffold: the remaining commands are wired but not implemented. Each
  // lands in its phase (see PLAN.md "Build order"). Until then, fail loudly
  // rather than pretend success.
  process.stderr.write(
    `chaff ${invocation.command}: not implemented yet (scaffold). See PLAN.md build order.\n`,
  );
  return 1;
}

Promise.resolve(main(process.argv.slice(2))).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`chaff: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  },
);
