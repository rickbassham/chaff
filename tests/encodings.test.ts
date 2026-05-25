import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { encodedVariants } from '../src/encodings.js';

/**
 * Helper: the JSON-string-escaped inner form is `JSON.stringify(value)` with
 * the surrounding double-quotes removed.
 */
function jsonInner(value: string): string {
  const quoted = JSON.stringify(value);
  return quoted.slice(1, -1);
}

describe('encodedVariants (ac-1: each variant form)', () => {
  it('for a known ASCII value, the returned array contains the raw value unchanged', () => {
    const value = 'hello-world';
    expect(encodedVariants(value)).toContain(value);
  });

  it("for a known value, the returned array contains its standard-base64 encoding with padding (Buffer.from(value).toString('base64'))", () => {
    const value = 'hello';
    const std = Buffer.from(value).toString('base64');
    expect(std).toContain('=');
    expect(encodedVariants(value)).toContain(std);
  });

  it("for a known value, the returned array contains its standard-base64 encoding with trailing '=' padding stripped", () => {
    const value = 'hello';
    const std = Buffer.from(value).toString('base64');
    const stripped = std.replace(/=+$/, '');
    expect(stripped).not.toBe(std);
    expect(encodedVariants(value)).toContain(stripped);
  });

  it("for a value whose std-base64 contains '+' or '/', the returned array contains the url-safe variant with '+'→'-' and '/'→'_' (with padding)", () => {
    // '>>>' base64 is 'Pj4+' (contains '+'); '???' base64 is 'Pz8/' (contains '/').
    const value = '>>>???';
    const std = Buffer.from(value).toString('base64');
    expect(std).toMatch(/[+/]/);
    const urlSafe = std.replace(/\+/g, '-').replace(/\//g, '_');
    expect(encodedVariants(value)).toContain(urlSafe);
  });

  it('for that same value, the returned array contains the url-safe base64 variant with padding stripped', () => {
    const value = '>>>???';
    const std = Buffer.from(value).toString('base64');
    const urlSafe = std.replace(/\+/g, '-').replace(/\//g, '_');
    const urlSafeStripped = urlSafe.replace(/=+$/, '');
    expect(encodedVariants(value)).toContain(urlSafeStripped);
  });

  it("for a value containing reserved/space characters (e.g. 'a b&c=d'), the returned array contains its percent-encoding (encodeURIComponent form, e.g. 'a%20b%26c%3Dd')", () => {
    const value = 'a b&c=d';
    expect(encodeURIComponent(value)).toBe('a%20b%26c%3Dd');
    expect(encodedVariants(value)).toContain('a%20b%26c%3Dd');
  });

  it('for a value containing a double-quote, backslash, and newline, the returned array contains the JSON-string-escaped inner form matching JSON.stringify minus the surrounding quotes', () => {
    const value = 'a"b\\c\nd';
    const inner = jsonInner(value);
    expect(inner).toBe('a\\"b\\\\c\\nd');
    expect(encodedVariants(value)).toContain(inner);
  });

  it("for a known value, the returned array contains its lowercase-hex encoding (Buffer.from(value).toString('hex'))", () => {
    const value = 'hello';
    const hex = Buffer.from(value).toString('hex');
    expect(hex).toBe('68656c6c6f');
    expect(encodedVariants(value)).toContain(hex);
  });

  it('the function returns a string[] (array of strings), satisfying the `value → string[]` signature', () => {
    const result = encodedVariants('anything');
    expect(Array.isArray(result)).toBe(true);
    for (const entry of result) {
      expect(typeof entry).toBe('string');
    }
  });
});

describe('encodedVariants (ac-2: no I/O, deterministic)', () => {
  it('two successive calls with the same input return deeply-equal arrays (deterministic, no randomness)', () => {
    const value = '>>>???';
    expect(encodedVariants(value)).toEqual(encodedVariants(value));
  });

  it('the module source imports no I/O modules (no node:fs, node:net, node:child_process, node:crypto, process.env, console) — asserted by reading src/encodings.ts and checking the import/reference set', () => {
    const sourcePath = fileURLToPath(new URL('../src/encodings.ts', import.meta.url));
    const source = readFileSync(sourcePath, 'utf8');
    expect(source).not.toMatch(/node:fs/);
    expect(source).not.toMatch(/node:net/);
    expect(source).not.toMatch(/node:child_process/);
    expect(source).not.toMatch(/node:crypto/);
    expect(source).not.toMatch(/process\.env/);
    expect(source).not.toMatch(/\bconsole\b/);
  });

  it('calling the function does not mutate or read process.env (env snapshot before === after; no env key referenced)', () => {
    const before = JSON.stringify(process.env);
    encodedVariants('SOME_SECRET_VALUE');
    const after = JSON.stringify(process.env);
    expect(after).toBe(before);
  });
});

describe('encodedVariants (ac-3: known value + dedup)', () => {
  it('for a fixed known value, the full returned set equals the exact expected array of variant strings (raw, base64 std±pad, url-safe ±pad, percent, json-escape, hex)', () => {
    // Chosen so all eight forms are genuinely distinct: base64 'Ij4+Pwo=' has
    // '=' padding (std ±pad differ) and a '+' (url-safe differs from std), and
    // the '"', '>', '?', '\n' chars make percent-encoding and JSON-escape both
    // differ from the raw value.
    const value = '">>?\n';
    const std = Buffer.from(value).toString('base64'); // 'Ij4+Pwo='
    const stdNoPad = std.replace(/=+$/, '');
    const urlSafe = std.replace(/\+/g, '-').replace(/\//g, '_');
    const urlSafeNoPad = urlSafe.replace(/=+$/, '');
    const percent = encodeURIComponent(value);
    const json = jsonInner(value);
    const hex = Buffer.from(value).toString('hex');

    const expected = [value, std, stdNoPad, urlSafe, urlSafeNoPad, percent, json, hex];
    expect(encodedVariants(value)).toEqual(expected);
  });

  it('the returned array contains no duplicate strings (new Set(result).size === result.length)', () => {
    const result = encodedVariants('a b&c=d');
    expect(new Set(result).size).toBe(result.length);
  });

  it("for a value whose std-base64 has no '+'/'/' so url-safe equals std, the duplicate url-safe form appears only once in the result", () => {
    const value = 'hello'; // base64 'aGVsbG8=' — no '+' or '/'
    const std = Buffer.from(value).toString('base64');
    expect(std).not.toMatch(/[+/]/);
    const result = encodedVariants(value);
    const count = result.filter((v) => v === std).length;
    expect(count).toBe(1);
  });

  it('for an all-ASCII-safe value where percent-encoding equals raw, the coincidental raw/percent collision is collapsed to a single entry', () => {
    const value = 'safevalue123'; // encodeURIComponent is identity
    expect(encodeURIComponent(value)).toBe(value);
    const result = encodedVariants(value);
    const count = result.filter((v) => v === value).length;
    expect(count).toBe(1);
  });

  it('for a value whose with/without-padding base64 variants coincide, the padding-collision is collapsed to a single entry', () => {
    const value = 'abc'; // base64 'YWJj' — no '=' padding, so ±pad coincide
    const std = Buffer.from(value).toString('base64');
    expect(std).not.toMatch(/=/);
    const result = encodedVariants(value);
    const count = result.filter((v) => v === std).length;
    expect(count).toBe(1);
  });
});
