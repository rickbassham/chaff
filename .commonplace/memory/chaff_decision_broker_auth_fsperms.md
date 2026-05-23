---
name: chaff_decision_broker_auth_fsperms
description: "Decision #1: broker auth is filesystem-perms only (0700 dir / 0600
  socket), NOT peer-cred. Node has no peer-cred API; would force a native dep."
type: project
relations:
  - to: chaff_overview
    type: child-of
---
**Decision #1 (locked 2026-05-23): broker auth = filesystem permissions only.**

Original plan used Unix peer-cred auth (`SO_PEERCRED`) + `/proc/<pid>/cmdline` audit. Both are unbuildable/unportable:
- **Verified on Node v24.13.0:** a live AF_UNIX server-side connection exposes only `_getpeername`, which returns `{}`. Core Node has NO peer-credential API (no uid/gid/pid). Reading them needs a native addon → kills "no native deps".
- `SO_PEERCRED` is Linux-only; macOS uses `LOCAL_PEERCRED`/`getpeereid`.
- `/proc` does not exist on macOS (dev platform is Darwin).

For the accidental-leakage threat model, a `0600` socket inside a `0700` per-session dir under `$XDG_RUNTIME_DIR` (fallback `/tmp`) already enforces same-uid access via the OS. Peer-cred would only defend against a same-uid *hostile* process — out of scope.

**Result:** fs-perms is the trust boundary. Audit lines are broker-side `{ts, op, secretName}` — no peer pid/argv. Only `CHAFF_SOCK` (path, not a secret) exported to harness. Peer-cred + pid-tree gating → README "hardening (needs native addon)". `broker.ts` auth shrinks to "create socket in private dir with right mode + verify on startup".
