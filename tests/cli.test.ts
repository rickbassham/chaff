import { describe, it, expect } from 'vitest';
import {
  parseForceScrub,
  parseInvocation,
  parseRunArgs,
  isCommand,
  UsageError,
  COMMANDS,
} from '../src/cli.js';
import { parseForceScrubEnv } from '../src/exec.js';

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

describe('force-scrub NAME channel safety (DAR-1151)', () => {
  // Strategy chosen for AC-1: validate every --force-scrub NAME against the
  // env-var-name charset [A-Za-z_][A-Za-z0-9_]* at parse time. A valid NAME can
  // never contain the comma the CHAFF_FORCE_SCRUB channel joins on, so the
  // launcher join + exec split round-trip is unambiguous by construction.

  describe('ac-1: NAMEs are validated against the env-var-name charset at parse time', () => {
    it('parse of a force-scrub NAME matching [A-Za-z_][A-Za-z0-9_]* is accepted and returned verbatim', () => {
      const parsed = parseForceScrub(['--force-scrub', 'DEPLOY_ENV']);
      expect(parsed.forceScrub).toEqual(['DEPLOY_ENV']);
    });

    it('parse of a force-scrub NAME that violates the env-var-name charset (contains a comma) throws UsageError at parse time', () => {
      expect(() => parseForceScrub(['--force-scrub', 'FOO,BAR'])).toThrow(UsageError);
    });

    it('the channel keeps comma-joining and a NAME containing a comma is rejected at parse time (separator strategy alternative)', () => {
      expect(() => parseForceScrub(['--force-scrub', 'A,B'])).toThrow(UsageError);
    });

    it('round-trip across the channel: launcher join of an accepted NAME set then parseForceScrubEnv split returns the identical NAME list', () => {
      const { forceScrub } = parseForceScrub([
        '--force-scrub',
        'DEPLOY_ENV',
        '--force-scrub',
        'API_KEY',
        '--force-scrub',
        '_PRIVATE',
      ]);
      const channelValue = forceScrub.join(',');
      expect(parseForceScrubEnv(channelValue)).toEqual(forceScrub);
    });
  });

  describe('ac-2: a NAME containing the channel separator is rejected, never misinterpreted as multiple names', () => {
    it('a single force-scrub NAME containing the comma separator is rejected with UsageError at parse time (never reaches the channel as two entries)', () => {
      expect(() => parseForceScrub(['--force-scrub', 'FOO,BAR'])).toThrow(UsageError);
    });

    it('parseForceScrubEnv on a channel value built from accepted NAMEs never yields more entries than were serialized (no silent name multiplication)', () => {
      const { forceScrub } = parseForceScrub(['--force-scrub', 'ONE', '--force-scrub', 'TWO']);
      const channelValue = forceScrub.join(',');
      expect(parseForceScrubEnv(channelValue).length).toBe(forceScrub.length);
    });

    it('the rejection of a separator-containing NAME is a UsageError instance, matching the existing parse-time error contract', () => {
      expect(() => parseForceScrub(['--force-scrub', 'FOO,BAR'])).toThrow(UsageError);
      try {
        parseForceScrub(['--force-scrub', 'FOO,BAR']);
        expect.unreachable('expected parseForceScrub to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(UsageError);
      }
    });
  });

  describe('ac-3: `chaff run --force-scrub "FOO,BAR"` does not silently become two force-scrub entries', () => {
    it('parseRunArgs(["--force-scrub","FOO,BAR","--","tool"]) throws UsageError rather than producing ["FOO","BAR"]', () => {
      expect(() => parseRunArgs(['--force-scrub', 'FOO,BAR', '--', 'tool'])).toThrow(UsageError);
    });
  });
});

describe('isCommand', () => {
  it('accepts known commands and rejects others', () => {
    expect(isCommand('exec')).toBe(true);
    expect(isCommand('definitely-not')).toBe(false);
  });
});
