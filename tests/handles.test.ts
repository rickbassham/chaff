import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { formatHandle, parseHandle, isHandle } from '../src/handles.js';

describe('formatHandle (ac-1)', () => {
  it("formatHandle('OPENAI_API_KEY') matches /^chaff:1:OPENAI_API_KEY:[0-9a-f]{12}$/", () => {
    const handle = formatHandle('OPENAI_API_KEY');
    expect(handle).toMatch(/^chaff:1:OPENAI_API_KEY:[0-9a-f]{12}$/);
  });

  it('the nonce segment is exactly 12 chars and only [0-9a-f]', () => {
    const handle = formatHandle('SOME_NAME');
    const nonce = handle.split(':')[3];
    expect(nonce).toHaveLength(12);
    expect(nonce).toMatch(/^[0-9a-f]{12}$/);
  });

  it('two successive calls for the same name return different nonces', () => {
    const a = formatHandle('SAME_NAME');
    const b = formatHandle('SAME_NAME');
    expect(a.split(':')[3]).not.toBe(b.split(':')[3]);
  });

  it('a batch of >=1000 calls for the same name produces all-distinct nonces', () => {
    const nonces = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      nonces.add(formatHandle('SAME_NAME').split(':')[3]!);
    }
    expect(nonces.size).toBe(1000);
  });
});

describe('parseHandle / isHandle (ac-2)', () => {
  it("round-trip: parseHandle(formatHandle('DATABASE_URL')) recovers name, nonce, version", () => {
    const handle = formatHandle('DATABASE_URL');
    const embeddedNonce = handle.split(':')[3];
    const parsed = parseHandle(handle);
    expect(parsed).not.toBeNull();
    expect(parsed!.name).toBe('DATABASE_URL');
    expect(parsed!.nonce).toBe(embeddedNonce);
    expect(parsed!.version).toBe(1);
  });

  it("parseHandle('chaff:1:MY_TOKEN:0123456789ab') populates all three fields", () => {
    const parsed = parseHandle('chaff:1:MY_TOKEN:0123456789ab');
    expect(parsed).toEqual({ version: 1, name: 'MY_TOKEN', nonce: '0123456789ab' });
  });

  it("parseHandle returns null for a non-handle string ('plain-value')", () => {
    expect(parseHandle('plain-value')).toBeNull();
  });

  it("parseHandle returns null for a right-prefix wrong-nonce-length string ('chaff:1:NAME:abc')", () => {
    expect(parseHandle('chaff:1:NAME:abc')).toBeNull();
  });

  it('isHandle returns true for a value produced by formatHandle', () => {
    expect(isHandle(formatHandle('OPENAI_API_KEY'))).toBe(true);
  });

  it('isHandle returns false for a plain non-handle string and the empty string', () => {
    expect(isHandle('plain-value')).toBe(false);
    expect(isHandle('')).toBe(false);
  });

  it('isHandle(s) === (parseHandle(s) !== null) for valid and malformed inputs', () => {
    const valid = formatHandle('AGREE_NAME');
    const malformed = 'chaff:1:NAME:abc';
    expect(isHandle(valid)).toBe(parseHandle(valid) !== null);
    expect(isHandle(malformed)).toBe(parseHandle(malformed) !== null);
  });
});

describe('charset / round-trips (ac-3)', () => {
  it('every char of a handle is within [A-Za-z0-9:_-]', () => {
    const handle = formatHandle('SOME_NAME');
    expect(handle).toMatch(/^[A-Za-z0-9:_-]+$/);
  });

  it('survives an env round-trip unchanged and stays a handle', () => {
    const handle = formatHandle('ENV_ROUNDTRIP');
    process.env.CHAFF_TEST_HANDLE = handle;
    try {
      const readBack = process.env.CHAFF_TEST_HANDLE;
      expect(readBack).toBe(handle);
      expect(isHandle(readBack!)).toBe(true);
    } finally {
      delete process.env.CHAFF_TEST_HANDLE;
    }
  });

  it('survives a shell argv round-trip byte-identically (integration)', () => {
    const handle = formatHandle('SHELL_ROUNDTRIP');
    const out = execFileSync('/bin/sh', ['-c', 'printf %s "$1"', 'sh', handle], {
      encoding: 'utf8',
    });
    expect(out).toBe(handle);
    expect(isHandle(out)).toBe(true);
  });
});

describe('malformed-input rejection (ac-4)', () => {
  it('parseHandle rejects each malformed-input class with null', () => {
    // wrong literal prefix
    expect(parseHandle('xhaff:1:N:0123456789ab')).toBeNull();
    // too few ':' segments
    expect(parseHandle('chaff:1:0123456789ab')).toBeNull();
    // too many ':' segments
    expect(parseHandle('chaff:1:N:0123456789ab:extra')).toBeNull();
    // non-hex nonce
    expect(parseHandle('chaff:1:N:zzzzzzzzzzzz')).toBeNull();
    // empty string
    expect(parseHandle('')).toBeNull();
  });
});
