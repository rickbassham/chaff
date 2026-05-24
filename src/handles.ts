/**
 * Handle format helpers.
 *
 * A handle is the placeholder string that stands in for a secret env-var value
 * everywhere downstream (env, broker, scrubber). Its format is:
 *
 *   chaff:1:NAME:NONCE
 *
 * where NONCE is 12 random lowercase-hex characters. The nonce makes each
 * handle a unique, unguessable canary, and the whole string stays within
 * `[A-Za-z0-9:_-]` so it survives shell/env round-trips unchanged.
 *
 * This module is pure format plumbing — no broker, env, or CLI wiring.
 */

import { randomBytes } from 'node:crypto';

/** Literal version segment baked into every handle this module emits. */
const HANDLE_VERSION = 1;

/** Number of hex characters in the nonce segment. */
const NONCE_HEX_CHARS = 12;

/** Parsed components of a handle string. */
export interface Handle {
  version: number;
  name: string;
  nonce: string;
}

/**
 * Matches a full handle: literal `chaff`, the version, an arbitrary NAME
 * segment (anything but `:`), and a 12-char lowercase-hex nonce. Anchored so
 * extra leading/trailing characters or segments are rejected.
 */
const HANDLE_RE = new RegExp(`^chaff:(\\d+):([^:]+):([0-9a-f]{${NONCE_HEX_CHARS}})$`);

/** Build a fresh handle for `name` with a new random nonce. */
export function formatHandle(name: string): string {
  const nonce = randomBytes(NONCE_HEX_CHARS / 2).toString('hex');
  return `chaff:${HANDLE_VERSION}:${name}:${nonce}`;
}

/** Parse a handle string into its components, or return null if it is not one. */
export function parseHandle(str: string): Handle | null {
  const match = HANDLE_RE.exec(str);
  if (match === null) {
    return null;
  }
  const [, version, name, nonce] = match;
  return { version: Number(version), name: name!, nonce: nonce! };
}

/** Report whether `str` is a well-formed handle. */
export function isHandle(str: string): boolean {
  return HANDLE_RE.test(str);
}
