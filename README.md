# chaff

Keep environment-variable secrets out of an LLM coding harness's transcript.

When a harness (Claude Code, etc.) runs in a shell that already holds secrets
(`OPENAI_API_KEY`, `DATABASE_URL`, `*_TOKEN`), those values leak into the model's
transcript — which is sent to the provider and persisted. `chaff run` builds the
harness environment under a **default-deny** posture: only allowlisted vars pass
through verbatim, managed secrets are replaced by opaque **handles** (real
values held by an in-process broker), and **everything else is dropped** —
absent from the harness env entirely. It then resolves the real values only for
the child processes that need them, and scrubs known secret values out of child
output before the harness captures it.

> **Status: scaffold (Phase 0).** Commands are wired but not implemented. See
> [`PLAN.md`](./PLAN.md) for the design, the four locked review decisions, and the
> build order.

## Threat model

**Accidental leakage only.** chaff keeps secrets out of the history under
normal/buggy operation (misconfigured scripts, crash dumps, `set -x`, an LLM that
runs `echo $KEY`). It does **not** try to confine a hostile workload that actively
exfiltrates — a child holding the real value can always transform it or open its
own socket. Best-effort scrubbing is the bar.

**Default-deny, fail-safe over fail-open.** The harness env is built by _dropping
unknowns_, not by passing them through: a var is exposed only if it is on the
effective allowlist (passed through verbatim) or is a managed secret (replaced by
a handle). A var that is neither — including a secret the detection heuristics
miss and nobody listed — is **dropped**, never leaked. The cost is that an
unlisted var a tool genuinely needs goes missing (a tool may break, visibly),
which is the safe failure direction. Detection heuristics are **advisory** here,
not load-bearing for safety. See [`PLAN.md`](./PLAN.md) "Layer A — default-deny
harness env" for the full model.

See [`PLAN.md`](./PLAN.md) "Known gaps" for the documented residual gaps (notably:
a child that writes a secret to a file which is then read back via a non-Bash
tool).

## Development

```sh
make install       # pnpm install --frozen-lockfile
make build         # tsc -> dist/
make typecheck lint test format-check
```

Requires Node >= 20 (see `.nvmrc`) and pnpm.
