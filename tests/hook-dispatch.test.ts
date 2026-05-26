import { describe, it, expect } from 'vitest';
import { dispatchHook, type ReadDecision } from '../src/hook-dispatch.js';
import type { PreToolUseInput } from '../src/hook.js';

/** base64-encode a command string the way the hook wraps it. */
function b64(command: string): string {
  return Buffer.from(command, 'utf8').toString('base64');
}

/** A PreToolUse input for a Bash tool call with the given command. */
function bashInput(command: string): PreToolUseInput {
  return {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  };
}

/** A PreToolUse input for a read-family tool call targeting a path. */
function readInput(tool_name: string, file_path: string): PreToolUseInput {
  return {
    hook_event_name: 'PreToolUse',
    tool_name,
    tool_input: { file_path },
  };
}

/** A deny decision the injected secret-file/strict-reads stub returns. */
function deny(reason: string): ReturnType<ReadDecision> {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  };
}

/** A read decision fn that never decides (always passes through). */
const declines: ReadDecision = () => ({});

describe('dispatchHook — Bash routes to the base64-wrap decision (ac-1)', () => {
  it("a Bash tool call with command 'ls -la' is base64-wrapped via the default Bash decision, emitting hookSpecificOutput.updatedInput.command equal to `chaff exec --b64 '<b64>'`", () => {
    const out = dispatchHook(bashInput('ls -la'), { strictReads: false });
    expect(out.hookSpecificOutput?.updatedInput?.command).toBe(
      `chaff exec --b64 '${b64('ls -la')}'`,
    );
  });

  it('a Bash command already starting with `chaff exec --b64 ` is passed through with no rewrite (delegates to the idempotency guard)', () => {
    const already = `chaff exec --b64 '${b64('ls -la')}'`;
    const out = dispatchHook(bashInput(already), { strictReads: false });
    expect(out.hookSpecificOutput).toBeUndefined();
  });
});

describe('dispatchHook — Read/Glob/Grep route to the injected secret-file decision (ac-1)', () => {
  for (const tool of ['Read', 'Glob', 'Grep']) {
    it(`a ${tool} tool call is routed to the injected secret-file decision fn and its 'deny' output is returned verbatim`, () => {
      const out = dispatchHook(readInput(tool, '/repo/.env'), {
        strictReads: false,
        decideSecretFile: () => deny('stub'),
      });
      expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
      expect(out.hookSpecificOutput?.permissionDecisionReason).toBe('stub');
    });
  }

  it('when the injected secret-file fn declines (no decision), a Read emits no permissionDecision (the dispatcher never fabricates a deny)', () => {
    const out = dispatchHook(readInput('Read', '/repo/README.md'), {
      strictReads: false,
      decideSecretFile: declines,
    });
    expect(out.hookSpecificOutput?.permissionDecision).toBeUndefined();
    expect(out.hookSpecificOutput).toBeUndefined();
  });
});

describe('dispatchHook — --strict-reads gates the strict-reads routing leg (ac-1)', () => {
  for (const tool of ['Read', 'Grep', 'Glob']) {
    it(`when strictReads is true and the secret-file fn declines, a ${tool} is routed to the injected strict-reads fn and its decision is emitted`, () => {
      const out = dispatchHook(readInput(tool, '/repo/src/index.ts'), {
        strictReads: true,
        decideSecretFile: declines,
        decideStrictReads: () => deny('use Bash so chaff can scrub'),
      });
      expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
      expect(out.hookSpecificOutput?.permissionDecisionReason).toBe('use Bash so chaff can scrub');
    });
  }

  it('when strictReads is false, the strict-reads fn is NOT invoked for a Read input', () => {
    let invoked = false;
    const out = dispatchHook(readInput('Read', '/repo/src/index.ts'), {
      strictReads: false,
      decideSecretFile: declines,
      decideStrictReads: () => {
        invoked = true;
        return deny('should not run');
      },
    });
    expect(invoked).toBe(false);
    expect(out.hookSpecificOutput).toBeUndefined();
  });

  it('a secret-file deny takes priority: when the secret-file fn denies, the strict-reads fn is not consulted even with strictReads true', () => {
    let strictInvoked = false;
    const out = dispatchHook(readInput('Read', '/repo/.env'), {
      strictReads: true,
      decideSecretFile: () => deny('secret file'),
      decideStrictReads: () => {
        strictInvoked = true;
        return deny('strict');
      },
    });
    expect(strictInvoked).toBe(false);
    expect(out.hookSpecificOutput?.permissionDecisionReason).toBe('secret file');
  });
});
