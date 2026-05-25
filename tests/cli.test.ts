import { describe, it, expect } from 'vitest';
import { parseInvocation, parseRunArgs, isCommand, UsageError, COMMANDS } from '../src/cli.js';

describe('parseInvocation', () => {
  it('resolves each known command and splits trailing args', () => {
    for (const command of COMMANDS) {
      expect(parseInvocation([command, 'a', 'b'])).toEqual({ command, args: ['a', 'b'] });
    }
  });

  it('throws UsageError when no command is given', () => {
    expect(() => parseInvocation([])).toThrow(UsageError);
  });

  it('throws UsageError on an unknown command', () => {
    expect(() => parseInvocation(['frobnicate'])).toThrow(UsageError);
  });
});

describe('parseRunArgs', () => {
  it('stops --force-scrub parsing at the first `--`: a --force-scrub inside the harness command is preserved, not consumed', () => {
    const parsed = parseRunArgs(['--force-scrub', 'A', '--', 'tool', '--force-scrub', 'B']);
    expect(parsed.forceScrub).toEqual(['A']);
    expect(parsed.harnessArgs).toEqual(['tool', '--force-scrub', 'B']);
  });

  it('collects every --force-scrub before `--` and returns the harness command after it', () => {
    const parsed = parseRunArgs([
      '--force-scrub',
      'A',
      '--force-scrub',
      'B',
      '--',
      'mytool',
      '--flag',
    ]);
    expect(parsed.forceScrub).toEqual(['A', 'B']);
    expect(parsed.harnessArgs).toEqual(['mytool', '--flag']);
  });

  it('with no `--` separator, extracts --force-scrub pairs and treats the leftover as the harness command', () => {
    const parsed = parseRunArgs(['--force-scrub', 'A', 'mytool', 'arg']);
    expect(parsed.forceScrub).toEqual(['A']);
    expect(parsed.harnessArgs).toEqual(['mytool', 'arg']);
  });

  it('throws UsageError on a trailing --force-scrub with no NAME in the option segment', () => {
    expect(() => parseRunArgs(['--force-scrub'])).toThrow(UsageError);
  });

  it('does not throw when a bare `--force-scrub` token appears only after `--` (it is harness verbatim)', () => {
    const parsed = parseRunArgs(['--', 'tool', '--force-scrub']);
    expect(parsed.forceScrub).toEqual([]);
    expect(parsed.harnessArgs).toEqual(['tool', '--force-scrub']);
  });
});

describe('isCommand', () => {
  it('accepts known commands and rejects others', () => {
    expect(isCommand('exec')).toBe(true);
    expect(isCommand('definitely-not')).toBe(false);
  });
});
