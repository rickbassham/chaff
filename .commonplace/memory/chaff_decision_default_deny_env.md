---
name: chaff_decision_default_deny_env
description: "Decision: `chaff run` builds the harness env default-deny
  (allowlist + shipped defaults), NOT denylist secret-detection. Detection
  demoted to advisory. Fail-safe over fail-open. Supersedes the denylist framing
  in DAR-1094/launcher."
type: project
relations:
  - to: chaff_overview
    type: child-of
---
**Decision (2026-05-24): `chaff run` uses a default-deny (allowlist) env, not denylist secret-detection.**

## Why
The shipped Layer A is a denylist: detect secrets → handles, pass everything else through (`launcher.ts buildHarnessEnv`, the `else { env[name] = value }` branch). Failure mode is **fail-open** — a secret the heuristics miss passes through in the clear. For a security tool, allowlist beats denylist: an unlisted var is simply *absent*, so a missed secret is dropped (fail-safe: a tool breaks, visibly) rather than leaked (silent, unrecoverable).

## Model
Harness env = **{ allowlisted pass-through } ∪ { handles for managed secrets } ∪ { CHAFF_SOCK }**; everything else dropped (name and value). Chokepoint is the same `buildHarnessEnv`; spawn already uses an explicit `env` (no `process.env` inheritance), so the interception is already there — we just put less in.
- **Pass-through allowlist:** shipped sensible defaults (PATH, HOME, SHELL, TERM, LANG/LC_*, TZ, TMPDIR, USER, LOGNAME, PWD, XDG_*, …) + user-level + folder-level config, merged.
- **Managed secrets (→ handles):** detected-secret ∪ user-declared. Detection stays useful (auto-manage obvious secrets so tools work) but is **no longer load-bearing for safety** — a missed-and-unlisted secret is dropped, not leaked. Demoted to: (a) suggest the managed set / power `chaff scan`, (b) tripwire warning if an allowlisted var looks secret-like.
- **Everything else:** dropped.

## Open design point for the issue(s)
Exact precedence when a var is both allowlisted AND detected-secret (warn + treat as handle, probably). And how managed secrets are declared vs auto-detected.

## Costs (honest)
- **Breakage** is the real cost: tools depend on ambient vars (proxies, locale, SSH_AUTH_SOCK, toolchain dirs). Needs a good default allowlist + easy folder overrides. Failure shifts leak→breakage (correct direction).
- **Folder-level allowlist is a trust vector** (a checked-in `.chaff` could pass/exfil a secret). Guard: folder can't override a user "never-pass" set; folder-allowlisting a secret-looking var warns/confirms. Mostly beyond the accidental-leakage threat model, but noted.

## Scope vs shipped work
Unaffected: broker, exec (DAR-1101), scrubber. Revised: `buildHarnessEnv`, `policy.ts` (partially supersedes DAR-1094 framing), new config loading, `chaff scan` (3 buckets: passthrough/handle/dropped), banner (dropped count), PLAN.md + README threat model (pull channel becomes default-deny). Harness-agnostic (claude/codex/etc.) — Layer A spawns any command with a controlled env.