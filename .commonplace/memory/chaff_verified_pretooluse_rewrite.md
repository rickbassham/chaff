---
name: chaff_verified_pretooluse_rewrite
description: "VERIFIED empirically (Claude Code 2.1.150): PreToolUse honors
  hookSpecificOutput.updatedInput.command for Bash at execution time. Layer D
  enforcement is viable."
type: project
relations:
  - to: chaff_overview
    type: child-of
  - to: chaff_decision_base64_hook_wrap
    type: related-to
---
**Verified 2026-05-23 — the load-bearing assumption for Layer D holds.**

Question (DAR-1103 spike): does Claude Code actually APPLY `hookSpecificOutput.updatedInput.command` to a Bash tool call at execution time? Docs confirmed the JSON shape but not enforcement.

## Method (isolated, /tmp/chaff-spike)
- `.claude/settings.json` registered a PreToolUse hook on `Bash` with `permissions.allow: ["Bash"]`.
- Hook rewrote EVERY Bash command to `echo CHAFF_SPIKE_REWRITE_OK` and logged each firing to `hook-fired.log`.
- Ran headless `claude -p "...run: echo CHAFF_SPIKE_ORIGINAL_RAN"` with `--output-format stream-json --verbose`.
- `REWRITE_OK` appears nowhere in the prompt — so any occurrence proves the rewritten command executed.

## Result
- `hook-fired.log`: `HOOK_FIRED orig=[echo CHAFF_SPIKE_ORIGINAL_RAN]` (hook fired, saw the original).
- `CHAFF_SPIKE_REWRITE_OK` count = 3 in the transcript → the rewritten command is what ran.
- **Verdict: ✅ honored on Claude Code 2.1.150.**

## Notes
- The nested `claude` run could not be spawned by the agent's own Bash tool (auto-mode classifier blocks nested-agent spawns, esp. with `--dangerously-skip-permissions`). The user ran it via the `!` prefix instead.
- Caveat: confirmed on 2.1.150; re-check if Claude Code's hook behavior changes in a future version.
- Field names confirmed: rewrite via `hookSpecificOutput.updatedInput.command`; deny via `hookSpecificOutput.permissionDecision: "deny"` + `permissionDecisionReason`.
