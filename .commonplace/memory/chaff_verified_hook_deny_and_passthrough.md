---
name: chaff_verified_hook_deny_and_passthrough
description: "VERIFIED (CC 2.1.150): PreToolUse `deny`+reason blocks a Read (no
  leak); a hook `allow`+updatedInput authorizes the REWRITTEN command with NO
  separate allow rule (install-hooks needs no chaff exec rule)."
type: project
relations:
  - to: chaff_overview
    type: child-of
  - to: chaff_verified_pretooluse_rewrite
    type: builds-on
  - to: chaff_decision_disk_readback_gap
    type: related-to
---
**Verified 2026-05-23 (Claude Code 2.1.150)** — second spike round, isolated rigs under `/tmp/chaff-spike-{perm,deny}`. Completes the Layer D de-risk that DAR-1103 started.

## Test A — permission passthrough (`/tmp/chaff-spike-perm`)
- Bash-matcher hook returns `permissionDecision: allow` + `updatedInput.command` rewriting to `echo CHAFF_PASSTHRU_OK`. **No `Bash` allow rule** in settings.
- Result: hook fired; `CHAFF_PASSTHRU_OK` appeared 3× in the transcript; no permission errors in stderr.
- **Conclusion:** a hook's own `allow` authorizes the REWRITTEN command. The harness does NOT re-check the rewritten `chaff exec ...` against permission rules.
- **Implication:** `chaff install-hooks` (DAR-1107) does NOT need to add a separate allow rule for `chaff exec`. Scope unchanged.

## Test B — deny enforcement (`/tmp/chaff-spike-deny`)
- Read-matcher hook returns `permissionDecision: deny` + `permissionDecisionReason`. A `secret.env` held canary `DENY_SPIKE_LEAK_CANARY_7f3a9`.
- Result: deny hook fired; canary leak count = 0; the model acknowledged the deny reason 3×.
- **Conclusion:** `deny` genuinely blocks the Read; secret-file contents never reach the transcript.
- **Implication:** secret-file deny-list (DAR-1105) and `--strict-reads` (DAR-1106) are viable as designed.

## Caveat
All verified on 2.1.150; re-check on Claude Code upgrades.
