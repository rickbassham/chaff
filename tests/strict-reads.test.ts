import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decideStrictReads } from '../src/strict-reads.js';
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

describe('decideStrictReads — denies read-family tools (ac-1)', () => {
  it("decideStrictReads returns hookSpecificOutput.permissionDecision === 'deny' for a Read tool call, with a non-empty permissionDecisionReason string", () => {
    const out = decideStrictReads();
    expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(typeof out.hookSpecificOutput?.permissionDecisionReason).toBe('string');
    expect(out.hookSpecificOutput?.permissionDecisionReason?.length).toBeGreaterThan(0);
  });

  it("decideStrictReads denies all three read-family tools: a Read, a Glob, and a Grep input each yield permissionDecision 'deny'", () => {
    // The dispatcher routes all three read-family tools to decideStrictReads
    // under --strict-reads; each yields a deny (the decision is the same for any
    // read-family target, so the function ignores its input).
    expect(
      dispatchHook(readInput('/repo/src/index.ts'), { strictReads: true }).hookSpecificOutput
        ?.permissionDecision,
    ).toBe('deny');
    expect(
      dispatchHook(toolInput('Glob', { pattern: '**/*.ts' }), { strictReads: true })
        .hookSpecificOutput?.permissionDecision,
    ).toBe('deny');
    expect(
      dispatchHook(toolInput('Grep', { pattern: 'TODO', path: '/repo/src' }), { strictReads: true })
        .hookSpecificOutput?.permissionDecision,
    ).toBe('deny');
  });

  it('the strict-reads permissionDecisionReason steers the LLM to read via Bash cat/grep (the reason text names a Bash read path so the LLM is told to route through chaff exec / the scrubber rather than the denied native tool)', () => {
    const reason = decideStrictReads().hookSpecificOutput?.permissionDecisionReason;
    expect(reason).toBeDefined();
    // Names a Bash read path (cat/grep) and the chaff exec / scrubber routing.
    expect(reason).toMatch(/\bBash\b/);
    expect(reason).toMatch(/\bcat\b/);
    expect(reason).toMatch(/\bgrep\b/);
    expect(reason).toMatch(/chaff exec|scrub/);
  });

  it('the decision is shaped for the dispatcher: hookEventName === PreToolUse, deny/reason under hookSpecificOutput, no updatedInput key', () => {
    const out = decideStrictReads();
    expect(out.hookSpecificOutput?.hookEventName).toBe('PreToolUse');
    expect(out.hookSpecificOutput).toHaveProperty('permissionDecision');
    expect(out.hookSpecificOutput).toHaveProperty('permissionDecisionReason');
    expect(out.hookSpecificOutput).not.toHaveProperty('updatedInput');
  });

  it('src/strict-reads.ts is a pure leaf: references no process.stdin/stdout/env, child_process, or node:fs', () => {
    const source = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'strict-reads.ts'),
      'utf8',
    );
    expect(source).not.toMatch(/process\.stdin/);
    expect(source).not.toMatch(/process\.stdout/);
    expect(source).not.toMatch(/process\.env/);
    expect(source).not.toMatch(/child_process/);
    expect(source).not.toMatch(/node:fs/);
  });
});

describe('decideStrictReads — wired as the default strict-reads fn in dispatchHook (ac-1)', () => {
  it('dispatchHook with strictReads:true and the real decideStrictReads wired as default denies a Read whose path does NOT match any secret-file pattern (the deny is reachable through the default wiring without passing a stub)', () => {
    const out = dispatchHook(readInput('/repo/src/index.ts'), { strictReads: true });
    expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(out.hookSpecificOutput?.permissionDecisionReason?.length).toBeGreaterThan(0);
  });

  it('dispatchHook with strictReads:false (the default) does NOT deny a non-secret-file Read: it returns {} so Read proceeds — strict-reads is off by default', () => {
    const out = dispatchHook(readInput('/repo/src/index.ts'), { strictReads: false });
    expect(out).toEqual({});
  });

  it('a secret-file deny still takes priority over strict-reads: with strictReads:true, a Read targeting a .env path returns the secret-file deny reason (DAR-1105), not the strict-reads steer-to-Bash reason', () => {
    const strictReason = decideStrictReads().hookSpecificOutput?.permissionDecisionReason;
    const out = dispatchHook(readInput('/repo/.env'), { strictReads: true });
    expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
    // The reason is the secret-file deny, not the strict-reads steer.
    expect(out.hookSpecificOutput?.permissionDecisionReason).not.toBe(strictReason);
    expect(out.hookSpecificOutput?.permissionDecisionReason).toMatch(/secret-file name pattern/);
  });
});
