---
name: chaff_overview
description: "What chaff is: keeps env-var secrets out of LLM transcripts via
  handle substitution + egress scrubbing. Threat model, two leak channels,
  enforced path."
type: project
pinned: true
---
**chaff** is a standalone local CLI that keeps environment-variable secrets out of an LLM coding harness's transcript (Claude Code, etc.). Plan of record: `PLAN.md` at repo root.

## Core reframing
The orchestrator (LLM) and the workload (programs it runs) are different principals. The LLM only needs to *cause* a secret to be used; the child process needs the real value. So the LLM composes/triggers commands that consume secrets without the bytes entering the transcript.

## Threat model: accidental leakage ONLY
Keep secrets out of history under normal/buggy operation (misconfigured scripts, crash dumps, `set -x`, an LLM running `echo $KEY`). Explicitly NOT confining a hostile workload that actively exfiltrates — a child with the real value can always transform it or open a socket. Best-effort scrubbing is the right bar.

## Two leak channels (drives the design)
1. **Pull** — LLM runs `env`/`echo $KEY`/`cat .env`. Fixed by *handle substitution*: harness env holds references (`chaff:1:NAME:NONCE`), not values.
2. **Push** — a child *emits* the secret (stack trace, debug log). Fixed only by *egress scrubbing*: a filter that knows the real values and redacts before capture.

## Enforced path (4 layers)
- **A** `chaff run -- claude`: classify env, start broker (unix socket), spawn harness with secret vars replaced by handles.
- **B/C** `chaff exec`: PreToolUse rewrites each Bash command to run under this; resolves handles → real values in child env, scrubs child stdout/stderr.
- **D** PreToolUse hook: wraps Bash commands, denies secret-file reads.

PostToolUse cannot rewrite output, so scrubbing must happen before capture — hence the Bash-only enforcement via PreToolUse `updatedInput.command`.

## Shape
TypeScript ESM, Node>=20, pnpm, vitest, eslint, prettier, Makefile, thin bins over testable modules. No native deps. Structural reference (not dependency): commonplace.
