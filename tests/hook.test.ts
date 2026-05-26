import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decideHookOutput, type PreToolUseInput } from '../src/hook.js';

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

/** base64-encode a command string the way the hook wraps it. */
function b64(command: string): string {
  return Buffer.from(command, 'utf8').toString('base64');
}

/** Build a minimal PreToolUse input for a Bash tool call with the given command. */
function bashInput(command: string): PreToolUseInput {
  return {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  };
}

/** The emitted command, or undefined when the hook emits no rewrite. */
function emittedCommand(input: PreToolUseInput): string | undefined {
  return decideHookOutput(input).hookSpecificOutput?.updatedInput?.command;
}

describe('decideHookOutput — wrap a Bash command (ac-1)', () => {
  it("given a PreToolUse input for a Bash tool call with command 'ls -la', the hook returns hookSpecificOutput.updatedInput.command equal to `chaff exec --b64 '<b64>'` where <b64> is Buffer.from('ls -la').toString('base64')", () => {
    const out = decideHookOutput(bashInput('ls -la'));
    expect(out.hookSpecificOutput?.updatedInput?.command).toBe(
      `chaff exec --b64 '${b64('ls -la')}'`,
    );
  });

  it('the emitted updatedInput.command lives under hookSpecificOutput.updatedInput.command (exact object path), not at any other key', () => {
    const out = decideHookOutput(bashInput('echo hi'));
    expect(out).toHaveProperty('hookSpecificOutput.updatedInput.command');
    // No stray top-level command/updatedInput keys.
    expect(out).not.toHaveProperty('command');
    expect(out).not.toHaveProperty('updatedInput');
  });

  it("a non-Bash tool call (e.g. tool_name 'Read') is passed through with no updatedInput.command rewrite emitted", () => {
    const out = decideHookOutput({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: '/etc/hosts' },
    });
    expect(out.hookSpecificOutput?.updatedInput?.command).toBeUndefined();
  });
});

describe('decideHookOutput — single-line, single-quoted blob (ac-2)', () => {
  it("for a long multi-line original command (contains embedded newlines), the emitted wrapper string contains exactly one newline-free `chaff exec --b64 '...'` token: the base64 blob portion matches /^[A-Za-z0-9+/=]+$/ and contains no \\n", () => {
    const command = `set -e
for i in 1 2 3; do
  echo "line $i"
done`;
    const wrapper = emittedCommand(bashInput(command));
    expect(wrapper).toBeDefined();
    expect(wrapper).not.toContain('\n');
    const match = /^chaff exec --b64 '([^']*)'$/.exec(wrapper!);
    expect(match).not.toBeNull();
    const blob = match![1]!;
    expect(blob).toMatch(/^[A-Za-z0-9+/=]+$/);
  });

  it("the blob in the emitted wrapper is delimited by single quotes: wrapper starts with `chaff exec --b64 '` and ends with `'`, with exactly one opening and one closing single quote around the blob", () => {
    const wrapper = emittedCommand(bashInput('cat file.txt'));
    expect(wrapper).toBeDefined();
    expect(wrapper!.startsWith("chaff exec --b64 '")).toBe(true);
    expect(wrapper!.endsWith("'")).toBe(true);
    // Exactly two single quotes total: the opening and closing delimiters.
    expect(wrapper!.split("'").length - 1).toBe(2);
  });
});

describe('decideHookOutput — idempotency guard (ac-3)', () => {
  it('given a Bash command that already starts with `chaff exec --b64 ` (a previously-wrapped command), the hook emits no updatedInput.command rewrite (passes through unchanged)', () => {
    const already = `chaff exec --b64 '${b64('ls -la')}'`;
    expect(emittedCommand(bashInput(already))).toBeUndefined();
  });

  it("a command that merely contains 'chaff exec --b64 ' in the middle (not at the start, e.g. `echo chaff exec --b64 foo`) is still wrapped, not treated as already-wrapped", () => {
    const command = 'echo chaff exec --b64 foo';
    expect(emittedCommand(bashInput(command))).toBe(`chaff exec --b64 '${b64(command)}'`);
  });
});

describe('decideHookOutput — pure, testable function (ac-4)', () => {
  it('the wrapping logic is an exported pure function that takes a parsed PreToolUse input object and returns the hook output object, with no stdin/stdout/process.env/child_process I/O (asserted by reading src/hook.ts and checking the import/reference set)', () => {
    const source = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'hook.ts'),
      'utf8',
    );
    expect(typeof decideHookOutput).toBe('function');
    // No I/O surfaces in the module.
    expect(source).not.toContain('process.stdin');
    expect(source).not.toContain('process.stdout');
    expect(source).not.toContain('process.env');
    expect(source).not.toContain('child_process');
    expect(source).not.toContain('node:fs');
    expect(source).not.toContain('node:child_process');
  });

  it('calling the function twice with the same parsed PreToolUse input returns deeply-equal output (deterministic, no randomness)', () => {
    const input = bashInput('grep -r foo .');
    expect(decideHookOutput(input)).toEqual(decideHookOutput(input));
  });
});

describe('decideHookOutput — round-trip decode (ac-5)', () => {
  /** Pull the blob out of an emitted wrapper, asserting the wrapper shape. */
  function blobOf(command: string): string {
    const wrapper = emittedCommand(bashInput(command));
    expect(wrapper).toBeDefined();
    const match = /^chaff exec --b64 '([^']*)'$/.exec(wrapper!);
    expect(match).not.toBeNull();
    return match![1]!;
  }

  it("round-trip: for a plain command, Buffer.from(<emitted blob>, 'base64').toString('utf8') exactly equals the original command string", () => {
    const command = 'npm run build';
    const blob = blobOf(command);
    expect(Buffer.from(blob, 'base64').toString('utf8')).toBe(command);
  });

  it('round-trip for a command containing pipes, single quotes, double quotes and a $VAR (e.g. `echo "$KEY" | grep -o \'x\' > out.txt`): decode of the emitted blob is byte-for-byte equal to the original, preserving pipes and quotes', () => {
    const command = `echo "$KEY" | grep -o 'x' > out.txt`;
    const blob = blobOf(command);
    expect(Buffer.from(blob, 'base64').toString('utf8')).toBe(command);
  });
});

describe('decideHookOutput — reusable PreToolUse fixture (ac-6)', () => {
  it("a reusable sample PreToolUse JSON fixture (Bash tool_name + tool_input.command) is loaded/parsed and the hook output's updatedInput.command equals the expected `chaff exec --b64 '<b64>'` wrapper for that fixture's command", () => {
    const fixture = JSON.parse(
      readFileSync(join(FIXTURES_DIR, 'pretooluse-bash.json'), 'utf8'),
    ) as PreToolUseInput;
    const original = fixture.tool_input.command!;
    expect(emittedCommand(fixture)).toBe(`chaff exec --b64 '${b64(original)}'`);
  });

  it('the fixture exercises the already-wrapped passthrough case: a fixture whose command already starts with `chaff exec --b64 ` yields no rewrite', () => {
    const fixture = JSON.parse(
      readFileSync(join(FIXTURES_DIR, 'pretooluse-bash-wrapped.json'), 'utf8'),
    ) as PreToolUseInput;
    expect(emittedCommand(fixture)).toBeUndefined();
  });
});
