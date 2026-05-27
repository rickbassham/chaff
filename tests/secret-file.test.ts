import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decideSecretFile } from '../src/secret-file.js';
import { dispatchHook } from '../src/hook-dispatch.js';
import type { PreToolUseInput } from '../src/hook.js';

/** A PreToolUse input for a Read tool call targeting a file_path. */
function readInput(file_path: string): PreToolUseInput {
  return {
    hook_event_name: 'PreToolUse',
    tool_name: 'Read',
    tool_input: { file_path },
  };
}

/** A PreToolUse input for a read-family tool call with an arbitrary tool_input. */
function toolInput(tool_name: string, tool_input: Record<string, unknown>): PreToolUseInput {
  return { hook_event_name: 'PreToolUse', tool_name, tool_input };
}

describe('decideSecretFile — denies secret-name patterns for Read (ac-1)', () => {
  it("a Read tool call whose tool_input.file_path basename is `.env` returns hookSpecificOutput.permissionDecision === 'deny' with a non-empty permissionDecisionReason string", () => {
    const out = decideSecretFile(readInput('/repo/.env'));
    expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(typeof out.hookSpecificOutput?.permissionDecisionReason).toBe('string');
    expect(out.hookSpecificOutput?.permissionDecisionReason?.length).toBeGreaterThan(0);
  });

  it('each name pattern denies a matching basename: `.env`, `.env.local` (.env*), `server.pem` (*.pem), `id_rsa`/`id_ed25519` (id_*), `private.key` (*.key), `credentials`/`credentials.json` (credentials*) each yield permissionDecision deny for a Read', () => {
    const matching = [
      '.env',
      '.env.local',
      'server.pem',
      'id_rsa',
      'id_ed25519',
      'private.key',
      'credentials',
      'credentials.json',
    ];
    for (const name of matching) {
      const out = decideSecretFile(readInput(`/repo/${name}`));
      expect(out.hookSpecificOutput?.permissionDecision, `${name} should deny`).toBe('deny');
    }
  });

  it('the deny fires for all three read-family tools: a Glob (tool_input.pattern) and a Grep (tool_input.pattern, and tool_input.path) targeting a secret-name pattern each return permissionDecision deny, not only Read', () => {
    const glob = decideSecretFile(toolInput('Glob', { pattern: '**/.env' }));
    expect(glob.hookSpecificOutput?.permissionDecision).toBe('deny');

    const grepPattern = decideSecretFile(toolInput('Grep', { pattern: 'config/id_rsa' }));
    expect(grepPattern.hookSpecificOutput?.permissionDecision).toBe('deny');

    const grepPath = decideSecretFile(
      toolInput('Grep', { pattern: 'TOKEN', path: '/repo/credentials.json' }),
    );
    expect(grepPath.hookSpecificOutput?.permissionDecision).toBe('deny');
  });

  it('a secret-name match is detected on the path basename regardless of directory: `/home/user/project/.env` and `./config/id_rsa` are denied (the leading directory does not defeat the pattern)', () => {
    expect(
      decideSecretFile(readInput('/home/user/project/.env')).hookSpecificOutput?.permissionDecision,
    ).toBe('deny');
    expect(
      decideSecretFile(readInput('./config/id_rsa')).hookSpecificOutput?.permissionDecision,
    ).toBe('deny');
  });

  it("the returned decision is shaped for the dispatcher: hookSpecificOutput.hookEventName === 'PreToolUse' and permissionDecision/permissionDecisionReason live under hookSpecificOutput (assignable to HookDispatchOutput), with no updatedInput key", () => {
    const out = decideSecretFile(readInput('/repo/.env'));
    expect(out.hookSpecificOutput?.hookEventName).toBe('PreToolUse');
    expect(out.hookSpecificOutput).toHaveProperty('permissionDecision');
    expect(out.hookSpecificOutput).toHaveProperty('permissionDecisionReason');
    expect(out.hookSpecificOutput).not.toHaveProperty('updatedInput');
  });

  it('the decision function is pure and deterministic: called twice with the same PreToolUse input it returns deeply-equal output, and src/secret-file.ts references no process.stdin/process.stdout/process.env/child_process/node:fs', () => {
    const input = readInput('/repo/.env');
    expect(decideSecretFile(input)).toEqual(decideSecretFile(input));

    const source = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'secret-file.ts'),
      'utf8',
    );
    expect(source).not.toMatch(/process\.stdin/);
    expect(source).not.toMatch(/process\.stdout/);
    expect(source).not.toMatch(/process\.env/);
    expect(source).not.toMatch(/child_process/);
    expect(source).not.toMatch(/node:fs/);
  });

  it("wired into dispatchHook: dispatchHook(readInput('Read','/repo/.env'), {strictReads:false}) — using the real injected secret-file fn as the default — returns permissionDecision deny (the deny is reachable without passing a stub)", () => {
    const out = dispatchHook(readInput('/repo/.env'), { strictReads: false });
    expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(out.hookSpecificOutput?.permissionDecisionReason?.length).toBeGreaterThan(0);
  });
});

describe('decideSecretFile — allows non-secret reads (ac-2)', () => {
  it("a Read of a `.env` file is denied: permissionDecision === 'deny' and permissionDecisionReason is a non-empty string", () => {
    const out = decideSecretFile(readInput('/repo/.env'));
    expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(out.hookSpecificOutput?.permissionDecisionReason?.length).toBeGreaterThan(0);
  });

  it('a Read of a normal source file (`/repo/src/index.ts`) is allowed: the function declines (returns exactly `{}`, no hookSpecificOutput), so the dispatcher emits no deny and the read proceeds', () => {
    expect(decideSecretFile(readInput('/repo/src/index.ts'))).toEqual({});
    const dispatched = dispatchHook(readInput('/repo/src/index.ts'), { strictReads: false });
    expect(dispatched).toEqual({});
  });

  it('non-secret names that superficially resemble a pattern do not over-deny: `environment.ts` (not .env*), `keyboard.ts` (not *.key), `credentialsHelper.ts` (not credentials*) — the basename-match semantics decline these', () => {
    for (const name of ['environment.ts', 'keyboard.ts', 'credentialsHelper.ts']) {
      expect(decideSecretFile(readInput(`/repo/${name}`)), `${name} should decline`).toEqual({});
    }
  });
});
