---
name: chaff_decision_base64_hook_wrap
description: "Decision #2: hook wraps Bash command as `chaff exec --b64
  '<base64>'`, NOT `chaff exec -- <cmd>`. Required for pipe topology AND $VAR
  expansion timing."
type: project
relations:
  - to: chaff_overview
    type: child-of
---
**Decision #2 (locked 2026-05-23): hook base64-wraps the command.**

The harness re-parses `hookSpecificOutput.updatedInput.command` through a shell. A naive `chaff exec -- <cmd>` breaks two ways (both demonstrated):
1. **Pipe/redirect topology:** `echo x | grep y` → `(chaff exec -- echo x) | grep y` — the harness shell parses the pipe, so `grep` runs OUTSIDE `chaff exec`.
2. **$VAR expansion timing (worse):** `tool --key $KEY` → `$KEY` expands in the *harness* shell where the var holds only the HANDLE → child receives handle text → tool FAILS. Defeats the tool's whole purpose. Plan's "resolve handle-valued env vars into child env" only helps programs reading `process.env` directly (e.g. `python script.py`), not `tool --key $VAR`.

**Decision:** `hook.ts` emits `chaff exec --b64 '<base64(originalCommand)>'`. `exec.ts` base64-decodes, resolves handle env vars into child env, runs decoded string under inner shell. Base64 defers BOTH shell-parsing and `$VAR` expansion to the inner shell (which has the real values). In TS `Buffer.from(cmd).toString('base64')` is single-line, alphabet `[A-Za-z0-9+/=]` (no shell metacharacters) → single safe token; single-quote anyway.

Idempotency guard: `command.startsWith('chaff exec --b64 ')` → passthrough.

**Open sub-decision:** inner shell choice. Plan said `$SHELL` (often zsh on macOS) but LLMs write bash-isms; lean `bash`, match the harness's shell. Confirm at Phase 4.

Verified 2026-05-23: Claude Code PreToolUse supports `updatedInput.command` rewrite and `permissionDecision: "deny"` + `permissionDecisionReason`.
