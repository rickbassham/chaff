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

See [`PLAN.md`](./PLAN.md) for the full design, the four locked review
decisions, and the build order.

## How it works (four layers)

| Layer                     | Job                                                                                                                                                                                              | Where                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------ |
| **A — default-deny env**  | Build the harness env: allowlisted vars verbatim, managed secrets → handles, everything else dropped. Closes the _pull_ channel (`echo $KEY`, `env`, `cat .env`).                                | `chaff run`                          |
| **B — handle resolution** | Resolve handle-valued env vars back to real values in the child process that needs them.                                                                                                         | `chaff exec`                         |
| **C — egress scrubbing**  | Stream the child's stdout/stderr through a redactor that replaces known secret values (and encoded variants) with `[redacted:NAME]`. Closes the _push_ channel (a child that prints the secret). | `chaff exec`                         |
| **D — enforce routing**   | A Claude Code `PreToolUse` hook transparently wraps every Bash command to run under `chaff exec`, and denies reads of obvious secret files.                                                      | `chaff install-hooks` + `chaff-hook` |

**Layers A, B, and C are harness-agnostic** — they are just `chaff run` and
`chaff exec`, usable under any harness (or by hand). **Layer D is
Claude-Code-specific**: it relies on Claude Code's `PreToolUse` hook contract
(rewriting `updatedInput.command`). A different harness would need its own
equivalent of the routing hook to get Layers B/C onto its tool calls; until then
it gets Layer A's pull-channel protection but not automatic egress scrubbing.

## Threat model

**Accidental leakage only.** chaff keeps secrets out of the transcript under
normal and buggy operation — a misconfigured script, a crash dump, `set -x`, an
LLM that runs `echo $KEY`, a tool that prints a stack trace containing a
`DATABASE_URL`. That is the whole bar.

chaff does **not** try to confine a _hostile_ workload. A child process that
holds the real value can always transform it (custom encoding, encryption) or
open its own socket and send it anywhere; **determined exfiltration by code the
LLM chooses to run is explicitly out of scope.** Best-effort scrubbing of
accidental emissions is the bar, not containment. The orchestrator (the LLM) and
the workload (the programs it runs) are treated as different principals: the LLM
only needs to _trigger_ a command that uses a secret, never to _see_ the bytes,
so chaff lets it compose and run such commands without the value entering the
transcript — but once a program is running with the real value, chaff cannot
police what that program does with it.

**Default-deny, fail-safe over fail-open.** The harness env is built by _dropping
unknowns_, not by passing them through: a var is exposed only if it is on the
effective allowlist (passed through verbatim) or is a managed secret (replaced by
a handle). A var that is neither — including a secret the detection heuristics
miss and nobody listed — is **dropped**, never leaked. The cost is that an
unlisted var a tool genuinely needs goes missing (a tool may break, visibly),
which is the safe failure direction. Detection heuristics are **advisory** here,
not load-bearing for safety. See [`PLAN.md` — Layer
A](./PLAN.md#layer-a--default-deny-harness-env) for the full model.

## Known gaps

These are documented because honest gap disclosure is part of the deliverable.
None of them are bugs to be fixed later by this tool's core design; they are the
boundary of what the threat model promises. See [`PLAN.md` — Known
gaps](./PLAN.md#known-gaps-document-in-readme-out-of-scope-for-v1) and the design
decisions it links to.

### #1 residual gap (open): disk write → read-back via a non-Bash tool

This is the **largest residual gap and it is not closed.** The scrubber (Layer C)
sits only on `chaff exec`'s stdout/stderr. A child can write a real secret to a
file by a descriptor chaff never sees — `printenv > debug.log`, a build log, a
crash dump — and chaff cannot observe arbitrary child writes without confining
the child (out of scope). The file can then be read back through Claude Code's
`Read`/`Grep`/`Glob` tools, which the hook can only **allow or deny, never
transform** (there is no `PostToolUse` rewrite, and a non-Bash tool can't be
routed through `chaff exec`). So a secret written to an arbitrarily-named file and
read back by a non-Bash tool reaches the transcript unscrubbed. See
[`PLAN.md` — decision
#4](./PLAN.md#4--disk-write--read-back-is-the-1-residual-accidental-gap-architectural).

Two **mitigations** exist, and they are partial — detective or opt-in, not a
fix:

- **`chaff scan`** greps the working tree for known secret values and warns if it
  finds one on disk. This is _detective_ — it tells you a secret already landed
  in a file, after the fact; it does not prevent the write or the read.
- **`--strict-reads`** (opt-in flag on the hook) makes the hook _deny_
  `Read`/`Grep`/`Glob` and steer the LLM to `cat`/`grep` via Bash, which _is_
  routed through the scrubber. It closes the read leg **only because the LLM is
  cooperative** in this threat model, and it is off by default because it costs
  `Read`'s line-numbering, chunking, and image support.

Also on this channel: the hook ships a **name-pattern deny-list** for
`Read`/`Grep`/`Glob` on obvious secret files (`.env*`, `*.pem`, `id_*`, `*.key`,
`credentials*`). That blocks the _obvious_ names but **misses arbitrary names**
like `debug.log`, which is exactly why this remains an open gap rather than a
solved one.

### Short legitimate secrets are not push-scrubbed by default

Egress scrubbing (Layer C) is gated by a **redaction-eligibility** check
(min-length AND min-entropy) that is _separate_ from secret classification. A
short or low-entropy value (a 6-char legacy key, a PIN, `prod`, `test`) would
turn the scrubber into a destructive find-replace — e.g. matching `cafe` inside a
build hash, or rewriting `npm test`. So such a value **still gets a handle** (the
pull channel is intact) but its **push-channel scrubbing is disabled by
default.** This is an **accepted, reported gap**: `chaff scan` and the launch
banner announce it loudly (`push-scrub OFF (handle still applies; output not scrubbed for):`), and
`chaff run --force-scrub NAME` is the explicit override that re-enables scrubbing
for a named secret while accepting possible output corruption. See [`PLAN.md` —
decision #3](./PLAN.md#3--redaction-eligibility-is-separate-from-classification).

### Determined exfiltration by chosen code — out of scope

As stated in the threat model: once the LLM runs a program with the real secret,
that program can encode, encrypt, or transmit the value however it likes. chaff
makes no attempt to stop this. It is **out of scope by the threat model**, not a
gap to be closed.

### Non-Claude harnesses

Layers A/B/C are harness-agnostic; **Layer D (the routing hook) is
Claude-Code-specific.** Under another harness you can still use `chaff run` and
`chaff exec` directly, but bare tool calls won't be auto-wrapped until that
harness has its own equivalent of the `PreToolUse` rewrite.

### Same-uid hostile process

The broker's trust boundary is filesystem permissions (a `0600` socket in a
`0700` per-session dir), which enforces _same-uid_ access via the OS. A same-uid
_hostile_ process is out of scope; peer-cred + pid-tree gating (which would need
a native addon) is noted as future hardening in
[`PLAN.md`](./PLAN.md#1--broker-auth-filesystem-permissions-only-was-peer-cred--proc-audit).

## Defense in depth: chaff is one control among several

chaff narrows exactly one channel — the transcript — and by design neither
confines the workload nor limits what a resolved credential can do. Two
complementary controls are worth pairing it with.

### Containers (host and network isolation)

A fair question: how much of this does a container (Docker, etc.) already
handle? Mostly a **different boundary** — the two are complementary, not
substitutes.

A container isolates the agent from the **host and the network**: unmounted
files (`~/.ssh`, `~/.aws`, other repos) aren't reachable, a stray `rm -rf` can't
escape, and `--network none` or an egress allowlist can stop arbitrary outbound
connections. chaff isolates secrets from the **transcript** — the tool output and
context sent to the model provider and persisted.

The reason a container cannot replace chaff's core: the transcript → provider
channel is **intended, authenticated traffic.** The agent must reach its provider
to function, so you cannot close that channel with a network policy — and it is
exactly the channel a leaked secret rides out on. Only keeping the raw value out
of the readable env (Layer A) and scrubbing it from child output (Layer C) help
there; a container has no hook into that traffic's content.

Mapping the [four layers](#how-it-works-four-layers) onto a container:

- **A / B / C — not replaceable.** A secret the child legitimately needs must be
  present in the container to be used; once it is, `echo $KEY` still surfaces it
  into the transcript. Container env is all-or-nothing (present and leakable, or
  absent and unusable) — it has no equivalent of handles, per-child resolution,
  or output scrubbing. The
  [#1 residual gap](#1-residual-gap-open-disk-write--read-back-via-a-non-bash-tool)
  survives inside a container for the same reason: the child holds the resolved
  value, so it can still write it to a file and read it back.
- **D's secret-file deny — a container does it better.** chaff's name-pattern
  deny-list is a heuristic that misses arbitrary names; simply not mounting the
  files removes them entirely.
- **Threats chaff punts on — a container covers.**
  [Determined exfiltration](#determined-exfiltration-by-chosen-code--out-of-scope)
  is out of chaff's scope by design; an egress-restricted container is a real
  control against it, as is host blast-radius containment.

Bottom line: run the agent **in a container _and_ under chaff** — the container
for host/network isolation, chaff for transcript hygiene on the one channel the
container must leave open. Layers A/B/C are harness-agnostic, so they run inside
a container unchanged.

### Principle of least privilege (limit what a credential can do)

chaff limits a secret's **visibility** — it never reaches the transcript — but
by design it does not limit that secret's **power.** Per the
[threat model](#threat-model), once a child resolves the real value chaff cannot
police what the program does with it: a `DATABASE_URL` for a superuser role can
still `DROP TABLE`, a full-access cloud key can still delete a bucket, with no
human in the loop. chaff controls _who can see_ the key; least privilege controls
_what the key can do._ Pair them.

Scope every credential the agent's tools resolve to the least authority the task
needs, so an accidental — or model-chosen — misuse has a bounded blast radius:

- **Databases:** hand the agent a role scoped to the schema/tables it needs,
  read-only where it can be, never a superuser/admin. A mistaken `DELETE`/`DROP`
  then fails on permissions instead of destroying data. Use distinct credentials
  per environment; never expose a prod-admin DSN to an agent session.
- **Cloud / IAM:** grant specific actions on specific resources, not
  `"Action": "*"` / `"Resource": "*"`; prefer short-lived (e.g. STS) credentials
  that expire and can be revoked.
- **API tokens:** use read-only or resource-scoped tokens rather than
  full-access keys, and rotate them.
- **Network:** combine with the container egress allowlist above, so even a
  misused credential can only reach intended endpoints.

The mindset: assume any secret an agent can use may eventually be used wrongly,
and ensure that when it is, the damage is small and recoverable. This is the
direct complement to chaff's bar — chaff shrinks the _chance_ of leakage, least
privilege shrinks the _cost_ of misuse.

## Manual end-to-end check

The unit and integration suites cover the mechanism in isolation, but the
end-to-end path — Claude Code's `PreToolUse` hook actually rewriting a real Bash
tool call, and the resolve+scrub round-trip happening upstream of transcript
capture — can only be confirmed against a **live Claude Code session**. The
procedure below is the manual acceptance check; the recorded result of running it
is in [Result](#result).

### Procedure

1. **Install the hook** into your Claude Code settings:

   ```sh
   chaff install-hooks
   ```

   This idempotently merges chaff's `PreToolUse` hook (matching
   `Bash|Read|Glob|Grep`) into `settings.json`.

2. **Launch Claude Code under `chaff run`**, with a secret already in the env:

   ```sh
   export OPENAI_API_KEY=sk-proj-REALVALUE...   # a real, eligible-length value
   chaff run -- claude
   ```

3. **Confirm the pull channel is closed.** In the session, ask the model to run:

   ```sh
   echo $OPENAI_API_KEY
   ```

   The transcript should show a **handle** of the form `chaff:1:OPENAI_API_KEY:<nonce>`,
   not the real value.

4. **Confirm the secret still works for a child that needs it.** Ask the model to
   run a script that consumes the key — for example a one-liner that reads
   `OPENAI_API_KEY` from its environment and makes an authenticated request, or
   simply asserts the value is the real one:

   ```sh
   node -e 'process.exit(process.env.OPENAI_API_KEY?.startsWith("sk-") ? 0 : 1)' && echo OK
   ```

   It should succeed (`OK`) — the child process received the resolved real value
   even though the harness env only holds the handle.

5. **Confirm the push channel is scrubbed.** Ask the model to echo the value
   back:

   ```sh
   printenv OPENAI_API_KEY
   ```

   Because the Bash command runs under `chaff exec`, the real value is redacted in
   the captured output to `[redacted:OPENAI_API_KEY]` before the transcript sees
   it.

### Result

Verified on 2026-05-27 (chaff at the DAR-1108 branch HEAD). The hook-rewrite and
resolve+scrub round-trip were exercised against the **built `chaff` /
`chaff-hook` binaries** by reproducing exactly what Claude Code's `PreToolUse`
hook does — feeding `Bash` tool-call JSON to `chaff-hook`, taking its
`updatedInput.command` rewrite, and running it under a `chaff run` broker (a
`bash` stand-in playing the harness role, with `OPENAI_API_KEY` set to a synthetic
eligible-length test value):

- `chaff-hook` rewrote `printenv OPENAI_API_KEY` to
  `chaff exec --b64 '<blob>'` (and denied a `Read` of `.env`).
- The harness env showed `OPENAI_API_KEY=chaff:1:OPENAI_API_KEY:<nonce>` — a
  handle, not the value (**pull channel closed**).
- A child `node -e` assertion that the resolved value starts with `sk` exited `0`
  (**child saw the real value**).
- `printenv OPENAI_API_KEY` came back as `[redacted:OPENAI_API_KEY]` in the
  captured output (**push channel scrubbed**).
- `install-hooks` merge + idempotency is covered by `tests/install-hooks.test.ts`
  (a re-run produces a byte-identical `settings.json`).

This confirms the full A→B→C→D mechanism end-to-end with the shipped binaries. It
was **not** run inside a live interactive Claude Code session against a real
provider key in this environment — running `chaff install-hooks` modifies the
agent's own `~/.claude/settings.json` and was intentionally not performed here.
The procedure above is the check to run in a real session; the binary-level
round-trip recorded here is the strongest end-to-end evidence obtainable without
mutating live agent config.

## Development

```sh
make install       # pnpm install --frozen-lockfile
make build         # tsc -> dist/
make verify        # format-check + lint + typecheck + test + build (the CI gate)
```

Requires Node and pnpm. The two Node-version sources in this repo are
deliberately different, not contradictory:

- **Supported floor: Node `>= 22`** — declared in `package.json` `engines.node`.
  This is the lowest version chaff supports, and CI tests against both Node 22
  and Node 24.
- **Recommended dev/latest: Node `24`** — pinned in `.nvmrc`, so `nvm use`
  lands on the version we develop against day to day.

In short: build on anything at or above the `>= 22` floor; for local
development, prefer the `24` that `.nvmrc` selects.
