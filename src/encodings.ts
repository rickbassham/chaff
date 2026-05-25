/**
 * Per-secret encoded-variant generation.
 *
 * Given a secret value, produce the set of encoded forms it might appear as in
 * child output, so the scrubber has something concrete to match against. The
 * forms are: the raw value, its base64 (standard and url-safe, each with and
 * without padding), percent-encoding, JSON-string-escape, and lowercase hex.
 *
 * This module is a pure, deterministic leaf: no I/O, no randomness, no env. It
 * only generates the candidate strings — deciding which are eligible for
 * redaction (DAR-1099) and matching them against streamed output (DAR-1102)
 * are downstream concerns handled by sibling modules.
 */

/** Strip trailing '=' base64 padding. */
function stripPadding(s: string): string {
  return s.replace(/=+$/, '');
}

/** Rewrite standard-base64 to the url-safe alphabet ('+'→'-', '/'→'_'). */
function toUrlSafe(s: string): string {
  return s.replace(/\+/g, '-').replace(/\//g, '_');
}

/** The JSON-string-escaped inner form: `JSON.stringify(value)` minus its quotes. */
function jsonStringEscape(value: string): string {
  const quoted = JSON.stringify(value);
  return quoted.slice(1, -1);
}

/**
 * Generate the deduped set of encoded forms `value` might appear as downstream.
 *
 * Coincidental collisions (e.g. an all-ASCII value where percent-encoding
 * equals the raw value, or base64 that needs no padding) are collapsed, with
 * first-occurrence order preserved.
 */
export function encodedVariants(value: string): string[] {
  const bytes = Buffer.from(value, 'utf8');
  const base64Std = bytes.toString('base64');
  const base64Url = toUrlSafe(base64Std);

  const variants = [
    value,
    base64Std,
    stripPadding(base64Std),
    base64Url,
    stripPadding(base64Url),
    encodeURIComponent(value),
    jsonStringEscape(value),
    bytes.toString('hex'),
  ];

  return [...new Set(variants)];
}
