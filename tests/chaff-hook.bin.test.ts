import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const HOOK_BIN = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'dist',
  'bin',
  'chaff-hook.js',
);

/** base64-encode a command the way the hook wraps it. */
function b64(command: string): string {
  return Buffer.from(command, 'utf8').toString('base64');
}

/** Spawn the built chaff-hook bin with the given stdin + argv. */
function runHook(
  stdin: string,
  args: string[] = [],
): { stdout: string; stderr: string; status: number } {
  if (!existsSync(HOOK_BIN)) {
    throw new Error(`built bin missing at ${HOOK_BIN}; run \`make build\` first`);
  }
  try {
    const stdout = execFileSync(process.execPath, [HOOK_BIN, ...args], {
      input: stdin,
      encoding: 'utf8',
    });
    return { stdout, stderr: '', status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
  }
}

/** A PreToolUse JSON string for a Bash tool call. */
function bashJson(command: string): string {
  return JSON.stringify({
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  });
}

describe('chaff-hook bin — base64-wraps a Bash command end-to-end (ac-1)', () => {
  it("writing a PreToolUse JSON for a Bash 'ls -la' to stdin makes the bin print hookSpecificOutput.updatedInput.command = `chaff exec --b64 '<b64>'` and exit 0", () => {
    const { stdout, status } = runHook(bashJson('ls -la'));
    expect(status).toBe(0);
    const out = JSON.parse(stdout) as {
      hookSpecificOutput?: { updatedInput?: { command?: string } };
    };
    expect(out.hookSpecificOutput?.updatedInput?.command).toBe(
      `chaff exec --b64 '${b64('ls -la')}'`,
    );
  });

  it("the bin's stdout is exactly one JSON value (JSON.parse of the whole stdout succeeds), with diagnostics kept off stdout", () => {
    const { stdout } = runHook(bashJson('echo hi'));
    expect(() => JSON.parse(stdout)).not.toThrow();
    // No trailing diagnostic text appended after the JSON value.
    expect(stdout.trim()).toBe(stdout.trim());
    expect(JSON.stringify(JSON.parse(stdout))).toBe(stdout.trim());
  });

  it('a Bash command already starting with `chaff exec --b64 ` is passed through with no updatedInput.command rewrite (idempotency guard)', () => {
    const already = `chaff exec --b64 '${b64('ls -la')}'`;
    const { stdout, status } = runHook(bashJson(already));
    expect(status).toBe(0);
    const out = JSON.parse(stdout) as {
      hookSpecificOutput?: { updatedInput?: { command?: string } };
    };
    expect(out.hookSpecificOutput).toBeUndefined();
  });

  it('malformed (non-JSON) stdin makes the bin fail loudly: non-zero exit, error on stderr, and no hookSpecificOutput rewrite on stdout', () => {
    const { stdout, stderr, status } = runHook('this is not json{');
    expect(status).not.toBe(0);
    expect(stderr).not.toBe('');
    expect(stdout).not.toContain('hookSpecificOutput');
  });
});

describe('chaff-hook bin — end-to-end base64 round-trip (ac-3)', () => {
  it('a sample Bash command wrapped by the bin decodes back to the original command', () => {
    const sample = `curl -s -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models | jq '.data[].id'`;
    const { stdout } = runHook(bashJson(sample));
    const out = JSON.parse(stdout) as {
      hookSpecificOutput?: { updatedInput?: { command?: string } };
    };
    const wrapped = out.hookSpecificOutput?.updatedInput?.command;
    expect(wrapped).toBe(`chaff exec --b64 '${b64(sample)}'`);
    const match = /^chaff exec --b64 '([^']*)'$/.exec(wrapped!);
    expect(match).not.toBeNull();
    expect(Buffer.from(match![1]!, 'base64').toString('utf8')).toBe(sample);
  });
});
