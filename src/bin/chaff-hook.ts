#!/usr/bin/env node
/**
 * Thin PreToolUse hook entry (DAR-1107). Reads the hook JSON from stdin, parses
 * `--strict-reads` from argv, calls the pure {@link dispatchHook} decision core,
 * and writes the resulting hook output as a single JSON value to stdout. All
 * diagnostics go to stderr so stdout stays a single parseable JSON value Claude
 * Code can consume.
 *
 * Fail-safe: malformed (non-JSON) stdin writes an error to stderr and exits
 * non-zero WITHOUT printing a rewrite. A parse failure must never silently allow
 * or mangle a command — the harness sees the non-zero exit and runs the original
 * tool call unchanged rather than a fabricated one.
 *
 * The base64-wrap logic lives in {@link import('../hook.js')} (DAR-1104); the
 * secret-file deny (DAR-1105) and `--strict-reads` (DAR-1106) decision functions
 * land in their siblings and are wired into {@link dispatchHook} when present.
 */

import { dispatchHook } from '../hook-dispatch.js';
import type { PreToolUseInput } from '../hook.js';

/** Read all of stdin to a UTF-8 string. */
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function main(argv: string[]): Promise<void> {
  const strictReads = argv.includes('--strict-reads');

  const raw = await readStdin();
  const input = JSON.parse(raw) as PreToolUseInput;

  const output = dispatchHook(input, { strictReads });
  process.stdout.write(JSON.stringify(output));
}

main(process.argv.slice(2)).catch((err: unknown) => {
  process.stderr.write(`chaff-hook: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
