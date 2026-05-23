# chaff

Keep environment-variable secrets out of an LLM coding harness's transcript.

When a harness (Claude Code, etc.) runs in a shell that already holds secrets
(`OPENAI_API_KEY`, `DATABASE_URL`, `*_TOKEN`), those values leak into the model's
transcript — which is sent to the provider and persisted. `chaff` replaces secret
values in the harness environment with opaque **handles**, resolves the real
values only for the child processes that need them, and scrubs known secret
values out of child output before the harness captures it.

> **Status: scaffold (Phase 0).** Commands are wired but not implemented. See
> [`PLAN.md`](./PLAN.md) for the design, the four locked review decisions, and the
> build order.

## Threat model

**Accidental leakage only.** chaff keeps secrets out of the history under
normal/buggy operation (misconfigured scripts, crash dumps, `set -x`, an LLM that
runs `echo $KEY`). It does **not** try to confine a hostile workload that actively
exfiltrates — a child holding the real value can always transform it or open its
own socket. Best-effort scrubbing is the bar.

See `PLAN.md` "Known gaps" for the documented residual gaps (notably: a child that
writes a secret to a file which is then read back via a non-Bash tool).

## Development

```sh
make install       # pnpm install --frozen-lockfile
make build         # tsc -> dist/
make typecheck lint test format-check
```

Requires Node >= 20 (see `.nvmrc`) and pnpm.
