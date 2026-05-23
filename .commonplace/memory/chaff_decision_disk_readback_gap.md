---
name: chaff_decision_disk_readback_gap
description: "Decision #4: child-writes-to-disk then read-back via
  Read/Grep/Glob is the #1 residual accidental gap (architectural). Mitigation:
  deny-list + chaff scan tree + opt-in --strict-reads."
type: project
relations:
  - to: chaff_overview
    type: child-of
---
**Decision #4 (locked 2026-05-23): disk write→read-back is the #1 residual accidental gap (architectural, no clean fix).**

The scrubber sits only on `chaff exec`'s stdout. Two legs slip past, both demonstrated:
1. **Write leg (unobservable):** a child redirecting to a file (`printenv > debug.log`) writes the real secret to a descriptor that isn't chaff's stdout → scrubber never sees it. chaff can't observe arbitrary child writes without confining the child (out of scope).
2. **Read leg (untransformable):** reading the file back via `Read`/`Grep`/`Glob` can only be ALLOWED or DENIED by the hook — NEVER transformed (no PostToolUse rewrite; a non-Bash tool can't route through `chaff exec`). Name-pattern deny-list misses arbitrary names like `debug.log`.

In scope by threat model (purely accidental) but no clean fix because scrubbing is Bash-only by construction.

**Decision (Option B):**
- Keep name-pattern deny-list on `Read`/`Grep`/`Glob` (`.env*`, `*.pem`, `id_*`, `*.key`, `credentials*`).
- Add working-tree scan to `chaff scan`: grep cwd for known redaction-set values, warn (detective).
- Ship `--strict-reads` as OPT-IN flag: hook denies `Read`/`Grep`/`Glob` with a reason steering the LLM to `cat`/`grep` via Bash (routed through scrubber). Closes read leg ONLY because the LLM is cooperative in this threat model. Off by default (loses Read's line-numbers/chunking/images).
- README documents this as the #1 residual accidental gap, explicitly not closed.

**Rejected:** targeted write-tracking (deny only chaff-written paths via cwd mtime snapshots) — detection inherently leaky (misses writes outside cwd, races); not worth v1 complexity.
