#!/usr/bin/env node
// Thin PreToolUse hook entry. Reads the hook JSON from stdin.
//
// Phase 0 scaffold: this is a safe no-op. Emitting no output and exiting 0 tells
// Claude Code "no decision", so the tool call proceeds unchanged. Phase 4 (see
// PLAN.md) adds command base64-wrapping and the secret-file deny-list here.

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function main(): Promise<void> {
  await readStdin(); // drained and discarded in the scaffold
}

main().catch((err: unknown) => {
  process.stderr.write(`chaff-hook: ${String(err)}\n`);
  process.exitCode = 1;
});
