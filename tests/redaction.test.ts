/**
 * DAR-1099 — redaction-eligibility gate (min-length + min-entropy, decision #3).
 *
 * The gate is a pure `(value, config) -> eligible?` decision, AND-combining a
 * configurable min-length and min-entropy (bits/char) with sane defaults. The
 * gated redaction-set construction behind it applies a per-encoded-variant
 * length check, dedupes, keeps a gate-failing secret's handle intact (only
 * push-scrub is disabled) and records the skip by NAME so the launch banner and
 * `chaff scan` can report it. `--force-scrub NAME` overrides the gate per named
 * secret. The streaming scrubber that consumes the set is DAR-1102 (out of scope).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_MIN_LENGTH,
  DEFAULT_MIN_ENTROPY_BITS_PER_CHAR,
  isRedactionEligible,
  buildRedactionSet,
  type GatedSecret,
} from '../src/redaction.js';
import { encodedVariants } from '../src/encodings.js';
import { formatLaunchBanner, buildHarnessEnv } from '../src/launcher.js';
import { formatScanReport, buildScanReport } from '../src/scan.js';
import { classify } from '../src/policy.js';
import { parseForceScrub } from '../src/cli.js';

/**
 * A long, high-entropy value that clears the default gate comfortably (length
 * and bits/char both well above the defaults). Used wherever a test needs a
 * "strong" secret that passes.
 */
const STRONG = 'Xq7-Zb9_Kp2-Mw4_Rt6-Yv8_';

/** Build a one-secret gated-set input. */
function oneSecret(name: string, value: string): GatedSecret[] {
  return [{ name, value }];
}

describe('ac-1: configurable min-length AND min-entropy with sane defaults', () => {
  it('with default thresholds, a value below the default min-length is rejected by the gate even when its bits/char is high', () => {
    // 'aB3$' — only 4 chars (< default min-length) but every char distinct, so
    // bits/char is maximal. Length alone must reject it.
    const value = 'aB3$';
    expect(value.length).toBeLessThan(DEFAULT_MIN_LENGTH);
    expect(isRedactionEligible(value, {})).toBe(false);
  });

  it('with default thresholds, a value at/above default min-length but below the default min-entropy (bits/char) is rejected', () => {
    // 'aaaaaaaaaa' — 10 chars (>= default min-length) but a single repeated
    // char, so bits/char is 0 (< default min-entropy). Entropy must reject it.
    const value = 'aaaaaaaaaa';
    expect(value.length).toBeGreaterThanOrEqual(DEFAULT_MIN_LENGTH);
    expect(isRedactionEligible(value, {})).toBe(false);
  });

  it('with default thresholds, a value clearing both the default min-length and default min-entropy is accepted', () => {
    expect(STRONG.length).toBeGreaterThanOrEqual(DEFAULT_MIN_LENGTH);
    expect(isRedactionEligible(STRONG, {})).toBe(true);
  });

  it('a caller-supplied min-length stricter than the default rejects a value that the default would accept (min-length is honored from config, AND-combined)', () => {
    expect(isRedactionEligible(STRONG, {})).toBe(true);
    expect(isRedactionEligible(STRONG, { minLength: STRONG.length + 1 })).toBe(false);
  });

  it('a caller-supplied min-entropy stricter than the default rejects a value that the default would accept (min-entropy is honored from config, AND-combined)', () => {
    expect(isRedactionEligible(STRONG, {})).toBe(true);
    // Push the entropy floor above any achievable bits/char to force rejection
    // while length still clears — proving the entropy term is honored.
    expect(isRedactionEligible(STRONG, { minEntropyBitsPerChar: 100 })).toBe(false);
  });

  it('the default min-length and default min-entropy constants are exported and have positive, finite sane-default values (length >= 8, bits/char > 0) so callers can omit config', () => {
    expect(Number.isFinite(DEFAULT_MIN_LENGTH)).toBe(true);
    expect(DEFAULT_MIN_LENGTH).toBeGreaterThanOrEqual(8);
    expect(Number.isFinite(DEFAULT_MIN_ENTROPY_BITS_PER_CHAR)).toBe(true);
    expect(DEFAULT_MIN_ENTROPY_BITS_PER_CHAR).toBeGreaterThan(0);
  });
});

describe('ac-2: per-encoded-variant length check before entering the redaction set', () => {
  it('given a value whose raw form clears the gate but whose generated variants include one shorter than min-length, the short variant is excluded from the redaction set while the longer variants are included', () => {
    // The raw value is the shortest of its variants (base64/hex only expand), so
    // the realizable "short variant excluded, long kept" case is a value
    // participating (here via force-scrub) whose per-variant length floor admits
    // some variants and drops others. 'test' → test(4), dGVzdA(6) dropped at
    // minLength 8; dGVzdA==(8), 74657374(8) kept.
    const value = 'test';
    const variants = encodedVariants(value);
    const set = buildRedactionSet({
      secrets: oneSecret('PASSWORD', value),
      forceScrub: ['PASSWORD'],
      config: { minLength: 8, minEntropyBitsPerChar: 0 },
    });
    const shortVariants = variants.filter((v) => v.length < 8);
    const longVariants = variants.filter((v) => v.length >= 8);
    expect(shortVariants.length).toBeGreaterThan(0);
    expect(longVariants.length).toBeGreaterThan(0);
    for (const v of shortVariants) {
      expect(set.patterns).not.toContain(v);
    }
    for (const v of longVariants) {
      expect(set.patterns).toContain(v);
    }
  });

  it('given a value whose every encoded variant clears the per-variant length check, all variants enter the redaction set', () => {
    const value = STRONG;
    const variants = encodedVariants(value);
    const set = buildRedactionSet({
      secrets: oneSecret('TOKEN', value),
      config: { minLength: 1, minEntropyBitsPerChar: 0 },
    });
    for (const v of variants) {
      expect(set.patterns).toContain(v);
    }
  });

  it('the per-variant length check is applied to each entry of encodedVariants(value), not only to the raw value (a long-raw / short-variant case proves the filter is per-variant)', () => {
    // Two variants of 'test' clear minLength 8 and two do not, so the result is a
    // strict subset of the variant set — the filter ran per entry, not once on
    // the value. (Force-scrub bypasses only the value-level gate, not the floor.)
    const value = 'test';
    const variants = encodedVariants(value);
    const set = buildRedactionSet({
      secrets: oneSecret('PASSWORD', value),
      forceScrub: ['PASSWORD'],
      config: { minLength: 8, minEntropyBitsPerChar: 0 },
    });
    expect(set.patterns.length).toBeGreaterThan(0);
    expect(set.patterns.length).toBeLessThan(variants.length);
    // Every surviving pattern individually clears the floor.
    for (const p of set.patterns) {
      expect(p.length).toBeGreaterThanOrEqual(8);
    }
  });

  it('the resulting redaction-set patterns are deduped (no variant string appears twice after filtering)', () => {
    // Two secrets sharing the same value produce overlapping variant sets; the
    // result must still be deduped.
    const set = buildRedactionSet({
      secrets: [
        { name: 'A', value: STRONG },
        { name: 'B', value: STRONG },
      ],
    });
    expect(new Set(set.patterns).size).toBe(set.patterns.length);
  });
});

describe('ac-3: gate-fail keeps the handle (pull-channel) but disables push-scrub, reported never silent', () => {
  it('a classified-secret value that fails the gate produces NO redaction patterns for that secret (push-scrub disabled) but is still present in the broker handle/secret set (pull-channel intact)', () => {
    // 'test' fails the gate (too short). The launcher still hands it a handle and
    // seeds the broker — pull-channel intact, independent of the redaction set.
    const snapshot = { DB_PASSWORD: 'test' };
    const build = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      declaredManaged: ['DB_PASSWORD'],
      sockPath: '/tmp/s.sock',
    });
    expect(build.handles).toContain('DB_PASSWORD');
    expect(build.secrets.some((s) => s.name === 'DB_PASSWORD' && s.value === 'test')).toBe(true);

    const set = buildRedactionSet({ secrets: oneSecret('DB_PASSWORD', 'test') });
    expect(set.patterns).not.toContain('test');
    expect(set.patterns).toHaveLength(0);
  });

  it('a classified-secret value that fails the gate yields a skip record naming the secret (by NAME, never its value) so it can be reported', () => {
    const set = buildRedactionSet({ secrets: oneSecret('DB_PASSWORD', 'test') });
    expect(set.skipped).toHaveLength(1);
    expect(set.skipped[0]!.name).toBe('DB_PASSWORD');
    expect(JSON.stringify(set.skipped)).not.toContain('test');
  });

  it('a classified-secret value that PASSES the gate produces redaction patterns and yields no skip record', () => {
    const set = buildRedactionSet({ secrets: oneSecret('API_KEY', STRONG) });
    expect(set.patterns).toContain(STRONG);
    expect(set.skipped).toHaveLength(0);
  });

  it('formatLaunchBanner renders a push-scrub-OFF line naming each gated-out secret when skip records are present, and renders no such line when there are none', () => {
    const snapshot = { API_KEY: STRONG };
    const build = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      declaredManaged: ['API_KEY'],
      sockPath: '/tmp/s.sock',
    });
    const withSkips = formatLaunchBanner(build, [{ name: 'DB_PASSWORD' }]);
    expect(withSkips).toMatch(/push-scrub/i);
    expect(withSkips).toContain('DB_PASSWORD');

    const noSkips = formatLaunchBanner(build, []);
    expect(noSkips).not.toMatch(/push-scrub/i);
  });

  it('formatScanReport renders a redaction-gate-skip line naming each gated-out secret when skip records are present, and renders no such line when there are none', () => {
    const report = buildScanReport({
      snapshot: { API_KEY: STRONG },
      classification: classify({ API_KEY: STRONG }, {}),
      allowlist: [],
      declaredManaged: ['API_KEY'],
    });
    const withSkips = formatScanReport(report, [{ name: 'DB_PASSWORD' }]);
    expect(withSkips).toMatch(/push-scrub/i);
    expect(withSkips).toContain('DB_PASSWORD');

    const noSkips = formatScanReport(report, []);
    expect(noSkips).not.toMatch(/push-scrub/i);
  });

  it('neither the banner nor the scan skip line ever contains the secret VALUE (only the NAME)', () => {
    const value = 'test';
    const set = buildRedactionSet({ secrets: oneSecret('DB_PASSWORD', value) });
    const snapshot = { OTHER: STRONG };
    const build = buildHarnessEnv({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      declaredManaged: ['OTHER'],
      sockPath: '/tmp/s.sock',
    });
    const banner = formatLaunchBanner(build, set.skipped);
    const report = buildScanReport({
      snapshot,
      classification: classify(snapshot, {}),
      allowlist: [],
      declaredManaged: ['OTHER'],
    });
    const scan = formatScanReport(report, set.skipped);
    expect(banner).toContain('DB_PASSWORD');
    expect(banner).not.toMatch(/\btest\b/);
    expect(scan).toContain('DB_PASSWORD');
    expect(scan).not.toMatch(/\btest\b/);
  });
});

describe('ac-4: optional --force-scrub NAME override', () => {
  it('with --force-scrub NAME for a secret that would otherwise fail the gate, that secret variants ARE added to the redaction set despite failing the gate', () => {
    // 'test' fails the value-level gate. Force-scrub overrides that gate so its
    // (length-eligible) variants enter; without the override the set is empty.
    const value = 'test';
    const eligibleVariants = encodedVariants(value).filter((v) => v.length >= DEFAULT_MIN_LENGTH);
    expect(eligibleVariants.length).toBeGreaterThan(0);
    const set = buildRedactionSet({
      secrets: oneSecret('DB_PASSWORD', value),
      forceScrub: ['DB_PASSWORD'],
    });
    expect(set.patterns.length).toBeGreaterThan(0);
    for (const v of eligibleVariants) {
      expect(set.patterns).toContain(v);
    }
    expect(set.skipped).toHaveLength(0);
  });

  it('--force-scrub NAME applies only to the named secret: a different gated-out secret not in the force-scrub set remains excluded', () => {
    const set = buildRedactionSet({
      secrets: [
        { name: 'DB_PASSWORD', value: 'test' },
        { name: 'PIN', value: 'prod' },
      ],
      forceScrub: ['DB_PASSWORD'],
    });
    // DB_PASSWORD's eligible variants are present; PIN contributes no patterns.
    expect(set.patterns.length).toBeGreaterThan(0);
    for (const v of encodedVariants('prod')) {
      expect(set.patterns).not.toContain(v);
    }
    expect(set.skipped.map((s) => s.name)).toEqual(['PIN']);
  });

  it('absent --force-scrub (the override is optional), gate behavior is unchanged and gated-out secrets stay excluded', () => {
    const set = buildRedactionSet({ secrets: oneSecret('DB_PASSWORD', 'test') });
    expect(set.patterns).toHaveLength(0);
    expect(set.skipped.map((s) => s.name)).toEqual(['DB_PASSWORD']);
  });

  it('the chaff CLI exposes a --force-scrub NAME option (repeatable / accepting a name) that flows into redaction-set construction', () => {
    // The CLI parser collects every --force-scrub NAME into a list of names.
    const parsed = parseForceScrub(['--force-scrub', 'DB_PASSWORD', '--force-scrub', 'PIN']);
    expect(parsed.forceScrub).toEqual(['DB_PASSWORD', 'PIN']);
    // And those names drive buildRedactionSet's override behavior: a name in the
    // parsed list overrides the value-level gate for that secret.
    const withOverride = buildRedactionSet({
      secrets: oneSecret('DB_PASSWORD', 'test'),
      forceScrub: parsed.forceScrub,
    });
    const withoutOverride = buildRedactionSet({ secrets: oneSecret('DB_PASSWORD', 'test') });
    expect(withOverride.patterns.length).toBeGreaterThan(0);
    expect(withoutOverride.patterns).toHaveLength(0);
  });
});

describe('ac-5: worked examples from the issue', () => {
  it('short value excluded: a value shorter than min-length (e.g. cafe) yields no redaction patterns', () => {
    const set = buildRedactionSet({ secrets: oneSecret('API_KEY', 'cafe') });
    expect(set.patterns).toHaveLength(0);
  });

  it('low-entropy dictionary word excluded: prod and test each fail the gate and yield no redaction patterns', () => {
    expect(buildRedactionSet({ secrets: oneSecret('ENV', 'prod') }).patterns).toHaveLength(0);
    expect(buildRedactionSet({ secrets: oneSecret('PASSWORD', 'test') }).patterns).toHaveLength(0);
  });

  it('strong value included: a long high-entropy secret clears the gate and its raw value enters the redaction set', () => {
    const set = buildRedactionSet({ secrets: oneSecret('API_KEY', STRONG) });
    expect(set.patterns).toContain(STRONG);
  });

  it('npm test non-corruption case: building the redaction set for PASSWORD=test produces no pattern equal to test, so a downstream literal replace over the string "npm test" would leave test intact', () => {
    const set = buildRedactionSet({ secrets: oneSecret('PASSWORD', 'test') });
    expect(set.patterns).not.toContain('test');
    // Demonstrate the non-corruption property a downstream scrubber would rely on.
    let output = 'npm test';
    for (const pattern of set.patterns) {
      output = output.split(pattern).join('[redacted:PASSWORD]');
    }
    expect(output).toBe('npm test');
  });

  it('per-variant length filtering: a value whose hex/base64 variant is shorter than min-length has that variant excluded from the redaction set (guards against collision with SHAs/checksums/tokens)', () => {
    // Force-scrub 'test' so it participates (overriding only the value gate); the
    // per-variant floor at minLength 8 still drops its short base64 form
    // dGVzdA(6) while keeping the 8-char base64 and hex forms.
    const value = 'test';
    const variants = encodedVariants(value);
    const set = buildRedactionSet({
      secrets: oneSecret('TOKEN', value),
      forceScrub: ['TOKEN'],
      config: { minLength: 8, minEntropyBitsPerChar: 0 },
    });
    const tooShort = variants.filter((v) => v.length < 8);
    expect(tooShort.length).toBeGreaterThan(0);
    for (const v of tooShort) {
      expect(set.patterns).not.toContain(v);
    }
    // The length-eligible hex/base64 forms are still scrubbed.
    expect(set.patterns).toContain('74657374'); // hex of 'test'
  });
});

describe('guard: redaction.ts is a pure leaf (no I/O, no env)', () => {
  it('the module source imports no I/O modules (no node:fs, node:net, node:child_process, process.env, console)', () => {
    const sourcePath = fileURLToPath(new URL('../src/redaction.ts', import.meta.url));
    const source = readFileSync(sourcePath, 'utf8');
    expect(source).not.toMatch(/node:fs/);
    expect(source).not.toMatch(/node:net/);
    expect(source).not.toMatch(/node:child_process/);
    expect(source).not.toMatch(/process\.env/);
    expect(source).not.toMatch(/\bconsole\b/);
  });
});
