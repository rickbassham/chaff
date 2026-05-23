---
name: chaff_decision_redaction_gate
description: "Decision #3: redaction-eligibility (safe to global-replace) is a
  SEPARATE gate from classification (is-it-a-secret). Min-length + min-entropy,
  or push-scrub is disabled (handle still applies)."
type: project
relations:
  - to: chaff_overview
    type: child-of
---
**Decision #3 (locked 2026-05-23): redaction-eligibility is separate from classification.**

The plan's entropy backstop only decides *"is this a secret"* (classification → gets a handle). It does NOT decide *"is this value safe to global-replace in output"*. A short/common secret value turns the scrubber into destructive find-replace (demonstrated): `PASSWORD=test` → `npm test` becomes `npm [redacted:DB_PASSWORD]`; `API_KEY=cafe` matched inside a build hash. Encoded variants of short values collide with SHAs/checksums/tokens.

**Decision:** add a second, orthogonal **redaction-eligibility** gate — configurable **min-length AND min-entropy** (start ~8 chars / ~2.5 bits-per-char, tune). Length catches short high-entropy values (`cafe`); entropy catches dictionary words that clear length (`prod`, `test`). Each *encoded variant* gets its own length check before entering the redaction set.

A secret that fails the gate STILL gets a handle (pull-channel intact); only push-channel scrubbing is disabled, and `chaff scan` + launch banner report it loudly. Optional `--force-scrub X` override accepts output corruption.

**Residual risk (README):** genuinely short legit secrets (6-char legacy keys, PINs) not push-scrubbed by default — accepted, reported gap.

Touches `policy.ts` (classification), `encodings.ts`/`scrubber.ts` (gated redaction-set construction), `chaff scan` (report).
