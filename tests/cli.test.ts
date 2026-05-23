import { describe, it, expect } from 'vitest';
import { parseInvocation, isCommand, UsageError, COMMANDS } from '../src/cli.js';

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

describe('isCommand', () => {
  it('accepts known commands and rejects others', () => {
    expect(isCommand('exec')).toBe(true);
    expect(isCommand('definitely-not')).toBe(false);
  });
});
