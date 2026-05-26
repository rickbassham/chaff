/**
 * Streaming egress scrubber (DAR-1102, PLAN.md "Layer C", decision #3).
 *
 * A Node {@link Transform} that sits on the child's stdout/stderr inside
 * `chaff exec` and redacts secret values *before* the harness captures them.
 * `PostToolUse` cannot rewrite output, so scrubbing must happen upstream of
 * capture; this Transform is where it happens.
 *
 * What it does on each chunk:
 *   - **literal multi-pattern match** — every gated redaction pattern (a secret's
 *     raw value plus its encoded variants from {@link encodedVariants}) is matched
 *     as raw bytes (not regex) and replaced with `[redacted:NAME]`, where NAME is
 *     the secret's env-var name, never its value. Literal (byte) matching avoids
 *     turning a value containing regex metacharacters into an accidental pattern.
 *   - **hold-back buffer** — a value can be split across `read()`/`write()`
 *     boundaries, so after scrubbing a chunk the Transform emits everything except
 *     the trailing `maxPatternLen-1` bytes (the largest a partial match could be),
 *     carrying that tail forward to be re-scanned with the next chunk. On stream
 *     end the held-back remainder is scrubbed once more and flushed in full, so no
 *     trailing bytes are dropped and a secret ending the stream is still matched.
 *   - **handle canary** — if a *handle* string (`chaff:1:NAME:nonce`) appears in
 *     the output it signals a bypassed secret use (a handle leaked to where a real
 *     value should have been resolved). The Transform fires `onCanary(NAME)` (a
 *     warning to chaff's own stderr) and `onAudit({op, secretName})` (an audit
 *     entry naming the secret, never the value). Handle bytes themselves are also
 *     treated as redaction patterns so they do not pass through verbatim; the
 *     surrounding innocent bytes are left intact.
 *
 * The pattern set is **consumed as given** — building the gated set is DAR-1099
 * ({@link buildRedactionSet}) and the encoded variants are DAR-1096
 * ({@link encodedVariants}); this module matches whatever patterns it is handed.
 * {@link redactionEntriesFromSecrets} is a thin name-preserving adapter over the
 * same gate so callers (exec wiring) get NAME-tagged entries the scrubber needs
 * to emit `[redacted:NAME]`.
 *
 * Matching is `indexOf`-per-pattern (fine for the dozens of secrets a session
 * holds; Aho-Corasick is noted in PLAN.md as a future optimization, out of scope
 * here — AC requires correct matching across boundaries, not a specific
 * algorithm).
 */

import { Transform } from 'node:stream';
import { Buffer } from 'node:buffer';
import { encodedVariants } from './encodings.js';
import { isRedactionEligible } from './redaction.js';

/** A secret's NAME and the literal byte patterns whose appearance is redacted. */
export interface RedactionEntry {
  /** The env-var name, e.g. `OPENAI_API_KEY`. Emitted in `[redacted:NAME]`. */
  name: string;
  /** Literal strings to redact (a secret's raw value + its encoded variants). */
  patterns: string[];
}

/** A handle string and the NAME it stands in for, for canary detection. */
export interface HandleEntry {
  /** The env-var name the handle substitutes for. Named in the canary warning. */
  name: string;
  /** The handle string (`chaff:1:NAME:nonce`) whose appearance is a canary. */
  handle: string;
}

/** A canary audit record: the op tag plus the leaked handle's NAME (never value). */
export interface CanaryAuditRecord {
  /** The audit op tag identifying a handle-leak canary event. */
  op: string;
  /** The NAME of the secret whose handle leaked — never the secret value. */
  secretName: string;
}

/** Options for {@link createScrubber}. */
export interface ScrubberOptions {
  /** The NAME-tagged redaction patterns to literal-match and replace. */
  entries: RedactionEntry[];
  /**
   * Handles whose appearance in output is a canary (a bypassed secret use).
   * Defaults to empty. Each handle is also matched and redacted like a pattern.
   */
  handles?: HandleEntry[];
  /**
   * Called with the secret NAME each time a handle first appears in the output,
   * for a warning to chaff's own stderr. Defaults to a no-op.
   */
  onCanary?: (name: string) => void;
  /**
   * Called with an audit record each time a handle first appears, to record the
   * canary in the audit log. Defaults to a no-op.
   */
  onAudit?: (record: CanaryAuditRecord) => void;
}

/** The audit op tag written when a handle leaks into scrubbed output. */
export const CANARY_AUDIT_OP = 'canary-handle-leak';

/** One literal byte pattern paired with the NAME its replacement token carries. */
interface CompiledPattern {
  /** The pattern bytes to search for. */
  bytes: Buffer;
  /** The replacement bytes (`[redacted:NAME]`) substituted on a match. */
  replacement: Buffer;
  /** True when this pattern is a handle, so a match fires the canary callbacks. */
  isHandle: boolean;
  /** The secret NAME — used for the canary callbacks when `isHandle`. */
  name: string;
}

/** Compile entries + handles into literal byte patterns, longest pattern first. */
function compilePatterns(options: ScrubberOptions): {
  patterns: CompiledPattern[];
  maxPatternLen: number;
} {
  const patterns: CompiledPattern[] = [];

  for (const entry of options.entries) {
    const replacement = Buffer.from(`[redacted:${entry.name}]`, 'utf8');
    for (const pattern of entry.patterns) {
      if (pattern.length === 0) {
        continue;
      }
      patterns.push({
        bytes: Buffer.from(pattern, 'utf8'),
        replacement,
        isHandle: false,
        name: entry.name,
      });
    }
  }

  for (const handle of options.handles ?? []) {
    if (handle.handle.length === 0) {
      continue;
    }
    patterns.push({
      bytes: Buffer.from(handle.handle, 'utf8'),
      replacement: Buffer.from(`[redacted:${handle.name}]`, 'utf8'),
      isHandle: true,
      name: handle.name,
    });
  }

  // Longest first so a longer pattern wins over a shorter one that is its prefix
  // (e.g. a raw value vs. a shorter encoded variant) at the same position.
  patterns.sort((a, b) => b.bytes.length - a.bytes.length);

  const maxPatternLen = patterns.reduce((max, p) => Math.max(max, p.bytes.length), 0);
  return { patterns, maxPatternLen };
}

/**
 * Scrub one buffer: replace every literal pattern occurrence with its
 * `[redacted:NAME]` token, scanning left-to-right and choosing the
 * earliest-starting, then longest, match at each position. Returns the scrubbed
 * bytes and the set of handle NAMEs that matched (for the canary callbacks).
 *
 * Pure over `buf`: it does not mutate input and holds no state, so the Transform
 * can call it on the rolling buffer each chunk and again on the final remainder.
 */
function scrubBuffer(
  buf: Buffer,
  patterns: CompiledPattern[],
): { output: Buffer; canaries: Set<string> } {
  const out: Buffer[] = [];
  const canaries = new Set<string>();
  let pos = 0;

  while (pos < buf.length) {
    // Find the earliest match at or after `pos`; among matches starting at the
    // same index, `patterns` is longest-first so the first hit there is longest.
    let bestIndex = -1;
    let best: CompiledPattern | undefined;
    for (const pattern of patterns) {
      const idx = buf.indexOf(pattern.bytes, pos);
      if (idx === -1) {
        continue;
      }
      if (bestIndex === -1 || idx < bestIndex) {
        bestIndex = idx;
        best = pattern;
      }
    }

    if (best === undefined || bestIndex === -1) {
      out.push(buf.subarray(pos));
      break;
    }

    // Emit the innocent bytes before the match, then the replacement token.
    out.push(buf.subarray(pos, bestIndex));
    out.push(best.replacement);
    if (best.isHandle) {
      canaries.add(best.name);
    }
    pos = bestIndex + best.bytes.length;
  }

  return { output: Buffer.concat(out), canaries };
}

/**
 * Create a streaming redaction {@link Transform} from a redaction set.
 *
 * The Transform keeps a rolling hold-back buffer: each `_transform` appends the
 * incoming chunk, scrubs the whole rolling buffer, then emits everything except
 * the trailing `maxPatternLen-1` bytes — those are retained so a pattern split
 * across the next chunk boundary is still matched. `_flush` scrubs and emits the
 * final remainder so no trailing bytes are lost and an end-of-stream secret is
 * still redacted.
 *
 * Each handle NAME fires {@link ScrubberOptions.onCanary} and
 * {@link ScrubberOptions.onAudit} the first time it is seen across the stream,
 * so a repeated handle does not spam the warning/audit sinks.
 */
export function createScrubber(options: ScrubberOptions): Transform {
  const { patterns, maxPatternLen } = compilePatterns(options);
  const onCanary = options.onCanary ?? (() => {});
  const onAudit = options.onAudit ?? (() => {});
  // The most we ever need to hold back is one byte short of the longest pattern;
  // a partial match cannot be longer than that and still be incomplete.
  const holdBack = Math.max(0, maxPatternLen - 1);

  let pending = Buffer.alloc(0);
  const firedCanaries = new Set<string>();

  function reportCanaries(canaries: Set<string>): void {
    for (const name of canaries) {
      if (firedCanaries.has(name)) {
        continue;
      }
      firedCanaries.add(name);
      onCanary(name);
      onAudit({ op: CANARY_AUDIT_OP, secretName: name });
    }
  }

  return new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      pending = Buffer.concat([pending, Buffer.from(chunk)]);
      const { output, canaries } = scrubBuffer(pending, patterns);
      reportCanaries(canaries);

      // Emit all but the trailing hold-back window; retain that tail for the next
      // chunk so a value straddling the boundary is matched once it's complete.
      if (output.length > holdBack) {
        const emit = output.subarray(0, output.length - holdBack);
        pending = Buffer.from(output.subarray(output.length - holdBack));
        callback(null, emit);
      } else {
        pending = Buffer.from(output);
        callback();
      }
    },
    flush(callback) {
      // No more bytes can complete a partial match: scrub and emit the remainder
      // in full so nothing is truncated and a stream-ending secret is redacted.
      const { output, canaries } = scrubBuffer(pending, patterns);
      reportCanaries(canaries);
      pending = Buffer.alloc(0);
      callback(null, output.length > 0 ? output : undefined);
    },
  });
}

/** A secret to build redaction entries from: its NAME and real VALUE. */
export interface ScrubberSecret {
  /** The env-var name, e.g. `OPENAI_API_KEY`. */
  name: string;
  /** The real secret value, gated and expanded into encoded variants. */
  value: string;
}

/**
 * Build NAME-tagged {@link RedactionEntry} list from secrets, honoring the
 * redaction-eligibility gate (DAR-1099): a secret whose value fails
 * {@link isRedactionEligible} contributes no entry (so a short/common value like
 * `prod`/`test` cannot corrupt innocent output), while an eligible secret
 * contributes an entry carrying its {@link encodedVariants}.
 *
 * This is the name-preserving adapter the scrubber needs: {@link buildRedactionSet}
 * dedupes patterns into a flat array without their NAMEs, but the scrubber must
 * emit `[redacted:NAME]`, so this keeps the per-secret NAME alongside its
 * variants. It consumes the gate; it does not change it.
 */
export function redactionEntriesFromSecrets(secrets: ScrubberSecret[]): RedactionEntry[] {
  const entries: RedactionEntry[] = [];
  for (const secret of secrets) {
    if (!isRedactionEligible(secret.value, {})) {
      continue;
    }
    entries.push({ name: secret.name, patterns: encodedVariants(secret.value) });
  }
  return entries;
}
