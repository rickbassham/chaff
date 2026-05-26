/**
 * Redaction-eligibility gate + gated redaction-set construction (DAR-1099,
 * PLAN.md decision #3).
 *
 * A second gate, **orthogonal to classification** ({@link classify}, DAR-1094):
 * classification decides *"is this a secret"* (→ gets a handle); this gate
 * decides *"is this value safe to global-replace in output"* (→ may be
 * push-scrubbed). The two are separate because a short or common secret value
 * (`PASSWORD=test`, `ENV=prod`, `API_KEY=cafe`) turns the scrubber into a
 * destructive find-replace — `npm test` → `npm [redacted:…]`, `cafe` matched
 * inside a build hash — and a short value's hex/base64 collides with SHAs,
 * checksums, and tokens.
 *
 * The gate AND-combines a configurable **min-length** and **min-entropy**
 * (Shannon bits/char) with sane defaults: length catches short high-entropy
 * values (`cafe`); entropy catches dictionary words that clear length (`prod`,
 * `test`). The gated set is built per-encoded-variant: each variant from
 * {@link encodedVariants} (DAR-1096) gets its **own** length check before
 * entering the redaction set, so a short variant of a long value never enters.
 *
 * A secret that fails the gate **still gets a handle** — the pull-channel is
 * built by the launcher and is independent of this set; only push-scrubbing is
 * disabled for it. That is recorded as a {@link RedactionSkip} (by NAME, never
 * the value) so the launch banner and `chaff scan` can report it loudly — never
 * silent. The optional `forceScrub` set overrides the gate for named secrets,
 * accepting possible output corruption.
 *
 * This module is a pure, deterministic leaf: no I/O, no randomness, no env. It
 * only produces the set; the streaming scrubber that consumes it is DAR-1102.
 */

import { encodedVariants } from './encodings.js';

/**
 * Default minimum value length for the gate. PLAN.md decision #3 starts at ~8
 * chars (to tune); short values cannot be safely global-replaced.
 */
export const DEFAULT_MIN_LENGTH = 8;

/**
 * Default minimum Shannon entropy (bits per character) for the gate. PLAN.md
 * decision #3 starts at ~2.5 bits/char (to tune); dictionary words that clear
 * the length floor (`prod`, `test`, `admin`) sit below this.
 */
export const DEFAULT_MIN_ENTROPY_BITS_PER_CHAR = 2.5;

/** Tunable gate thresholds. Both fields optional; sane defaults apply. */
export interface RedactionGateConfig {
  /** Minimum value length. Defaults to {@link DEFAULT_MIN_LENGTH}. */
  minLength?: number;
  /**
   * Minimum Shannon entropy in bits/char. Defaults to
   * {@link DEFAULT_MIN_ENTROPY_BITS_PER_CHAR}.
   */
  minEntropyBitsPerChar?: number;
}

/** A secret the gate operates on: its NAME and real VALUE. */
export interface GatedSecret {
  /** The env-var name, e.g. `OPENAI_API_KEY`. Used in skip records. */
  name: string;
  /** The real secret value, gated and (if eligible) variant-expanded. */
  value: string;
}

/**
 * A record that a secret was excluded from push-scrubbing by the gate. Carries
 * the NAME only — never the value — so it is safe to render in the launch
 * banner and `chaff scan` output.
 */
export interface RedactionSkip {
  /** The name of the gated-out secret. */
  name: string;
}

/** The gated redaction set: patterns to scrub, plus the skips to report. */
export interface GatedRedactionSet {
  /**
   * The deduped strings the scrubber should redact from output: the encoded
   * variants of every eligible secret that individually clear the per-variant
   * length check. First-occurrence order preserved.
   */
  patterns: string[];
  /** One record per secret excluded by the gate (NAME only). */
  skipped: RedactionSkip[];
}

/** Inputs to {@link buildRedactionSet}. */
export interface BuildRedactionSetOptions {
  /** The classified secrets to gate and (if eligible) expand into variants. */
  secrets: GatedSecret[];
  /** Gate thresholds. Defaults applied per field when omitted. */
  config?: RedactionGateConfig;
  /**
   * Names whose gate verdict is overridden so they ARE scrubbed despite failing
   * — the `--force-scrub NAME` override, accepting possible output corruption.
   * Defaults to empty.
   */
  forceScrub?: readonly string[];
}

/** Shannon entropy of `value` in bits per character (0 for the empty string). */
function bitsPerChar(value: string): number {
  if (value.length === 0) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/**
 * The pure gate decision: whether `value` is safe to global-replace in output.
 * AND-combines the min-length and min-entropy thresholds (both must clear);
 * either failing rejects the value. Defaults apply per omitted config field.
 */
export function isRedactionEligible(value: string, config: RedactionGateConfig): boolean {
  const minLength = config.minLength ?? DEFAULT_MIN_LENGTH;
  const minEntropy = config.minEntropyBitsPerChar ?? DEFAULT_MIN_ENTROPY_BITS_PER_CHAR;
  return value.length >= minLength && bitsPerChar(value) >= minEntropy;
}

/**
 * Build the gated redaction set from a list of classified secrets.
 *
 * For each secret: if it clears the value-level gate ({@link isRedactionEligible})
 * OR is named in `forceScrub`, its {@link encodedVariants} are generated and each
 * variant is admitted **only if it individually clears the min-length check**
 * (the per-variant filter that stops a short hex/base64 form from colliding with
 * SHAs/checksums/tokens). A secret that fails the value-level gate and is not
 * force-scrubbed contributes no patterns and yields a {@link RedactionSkip}
 * naming it.
 *
 * `forceScrub` overrides only the value-level gate — the named secret
 * participates despite low value-entropy/length. The per-variant length floor
 * still applies even to a forced secret: a 2-char variant should never be
 * global-replaced regardless, so the override accepts corruption from the
 * secret's *value-eligible-length* forms, not from collision-prone short ones.
 *
 * The resulting `patterns` are deduped across all secrets, preserving
 * first-occurrence order. Pure: derives its result solely from its arguments.
 */
export function buildRedactionSet(options: BuildRedactionSetOptions): GatedRedactionSet {
  const config = options.config ?? {};
  const minLength = config.minLength ?? DEFAULT_MIN_LENGTH;
  const forceScrub = new Set(options.forceScrub ?? []);

  const patterns: string[] = [];
  const seen = new Set<string>();
  const skipped: RedactionSkip[] = [];

  for (const secret of options.secrets) {
    const forced = forceScrub.has(secret.name);
    if (!forced && !isRedactionEligible(secret.value, config)) {
      // Value-level gate failed and not overridden: push-scrub disabled for this
      // secret. The handle/pull-channel is the launcher's concern, unaffected.
      skipped.push({ name: secret.name });
      continue;
    }
    for (const variant of encodedVariants(secret.value)) {
      // Per-variant length check: a variant below min-length is dropped so a
      // short form cannot collide with unrelated SHAs/checksums/tokens in
      // output. Applies even under force-scrub — the override accepts corruption
      // from the value's long forms, never from a collision-prone short one.
      if (variant.length < minLength) {
        continue;
      }
      if (!seen.has(variant)) {
        seen.add(variant);
        patterns.push(variant);
      }
    }
  }

  return { patterns, skipped };
}
