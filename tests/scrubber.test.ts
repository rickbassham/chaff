import { describe, it, expect } from 'vitest';
import { Transform } from 'node:stream';
import { Buffer } from 'node:buffer';
import { createScrubber, type RedactionEntry, type HandleEntry } from '../src/scrubber.js';
import { encodedVariants } from '../src/encodings.js';

/**
 * Drive a chunk list through a scrubber Transform and resolve with the
 * concatenated emitted output as a UTF-8 string. Writes each chunk with a
 * separate `write()` so chunk boundaries are real (exercising the hold-back
 * buffer), then `end()`s to trigger the final flush.
 */
function runScrubber(
  scrubber: Transform,
  chunks: Array<string | Buffer>,
): Promise<{ output: string; dataEvents: number }> {
  return new Promise((resolve, reject) => {
    const out: Buffer[] = [];
    let dataEvents = 0;
    scrubber.on('data', (chunk: Buffer) => {
      dataEvents++;
      out.push(Buffer.from(chunk));
    });
    scrubber.on('end', () => {
      resolve({ output: Buffer.concat(out).toString('utf8'), dataEvents });
    });
    scrubber.on('error', reject);
    for (const chunk of chunks) {
      scrubber.write(chunk);
    }
    scrubber.end();
  });
}

/** Build a single-secret redaction entry from a NAME and its raw value. */
function entryFor(name: string, value: string): RedactionEntry {
  return { name, patterns: encodedVariants(value) };
}

describe('ac-1: streaming Transform', () => {
  it('the exported scrubber is a node stream Transform instance (instanceof Transform) constructed from a redaction set', () => {
    const scrubber = createScrubber({ entries: [entryFor('SECRET', 'super-secret-value')] });
    expect(scrubber).toBeInstanceOf(Transform);
  });

  it('writing N small chunks then ending the stream yields output as readable data events without buffering the whole stream in memory (chunks are emitted before stream end, not only on flush)', async () => {
    // No patterns at all, so nothing is held except the hold-back window. With a
    // tiny pattern the hold-back window is tiny, so most chunks flush promptly as
    // separate data events rather than all on the final flush.
    const scrubber = createScrubber({ entries: [{ name: 'X', patterns: ['zz'] }] });
    const chunks = Array.from({ length: 20 }, (_, i) => `chunk-${i}-`);
    let dataBeforeEnd = 0;
    let ended = false;
    scrubber.on('data', () => {
      if (!ended) {
        dataBeforeEnd++;
      }
    });
    const done = new Promise<void>((resolve) => {
      scrubber.on('end', () => {
        ended = true;
        resolve();
      });
    });
    for (const c of chunks) {
      scrubber.write(c);
    }
    // Allow the event loop to deliver data events before we end.
    await new Promise((r) => setImmediate(r));
    scrubber.end();
    await done;
    expect(dataBeforeEnd).toBeGreaterThan(0);
  });
});

describe('ac-2: hold-back buffer', () => {
  it('a secret value delivered split across two write() calls at an interior byte boundary is still matched and replaced with [redacted:NAME] in the combined output', async () => {
    const value = 'super-secret-value-123';
    const scrubber = createScrubber({ entries: [entryFor('SECRET', value)] });
    const mid = Math.floor(value.length / 2);
    const { output } = await runScrubber(scrubber, [
      'before ' + value.slice(0, mid),
      value.slice(mid) + ' after',
    ]);
    expect(output).toBe('before [redacted:SECRET] after');
  });

  it('a secret split one byte per write() call across its full length is still matched and redacted (worst-case fragmentation)', async () => {
    const value = 'fragmented-secret-xyz';
    const scrubber = createScrubber({ entries: [entryFor('SECRET', value)] });
    const chunks = [...value].map((c) => c);
    const { output } = await runScrubber(scrubber, chunks);
    expect(output).toBe('[redacted:SECRET]');
  });

  it('after each non-final chunk, at most maxPatternLen-1 bytes (the length of the longest pattern minus one) are withheld from the emitted output; bytes earlier than that are passed through promptly, not held to stream end', async () => {
    const value = 'abcdefghij'; // longest pattern is one of its encoded variants
    const longest = Math.max(...encodedVariants(value).map((p) => Buffer.byteLength(p, 'utf8')));
    const scrubber = createScrubber({ entries: [entryFor('SECRET', value)] });

    const emittedBeforeEnd: Buffer[] = [];
    let ended = false;
    scrubber.on('data', (chunk: Buffer) => {
      if (!ended) {
        emittedBeforeEnd.push(Buffer.from(chunk));
      }
    });
    const done = new Promise<void>((resolve) => {
      scrubber.on('end', () => {
        ended = true;
        resolve();
      });
    });

    // One large innocent chunk with no secret in it.
    const innocent = 'x'.repeat(1000);
    scrubber.write(innocent);
    await new Promise((r) => setImmediate(r));
    const heldBack = innocent.length - Buffer.concat(emittedBeforeEnd).length;
    // At most maxPatternLen-1 bytes are withheld pending more input.
    expect(heldBack).toBeLessThanOrEqual(longest - 1);
    // And we did emit something promptly (not all held to flush).
    expect(Buffer.concat(emittedBeforeEnd).length).toBeGreaterThan(0);

    scrubber.end();
    await done;
  });

  it('on stream end the held-back remainder is flushed: a non-secret tail shorter than maxPatternLen-1 still appears verbatim in the final output (no truncation, no dropped trailing bytes)', async () => {
    const value = 'a-long-enough-secret-value';
    const scrubber = createScrubber({ entries: [entryFor('SECRET', value)] });
    const tail = 'tail'; // shorter than maxPatternLen-1, would sit in the hold-back window
    const { output } = await runScrubber(scrubber, ['head ', tail]);
    expect(output).toBe('head tail');
  });

  it('a secret whose final byte is the last byte of the stream (no trailing newline) is redacted, exercising match against the flushed remainder', async () => {
    const value = 'secret-at-the-very-end-000';
    const scrubber = createScrubber({ entries: [entryFor('SECRET', value)] });
    const { output } = await runScrubber(scrubber, ['prefix:' + value]);
    expect(output).toBe('prefix:[redacted:SECRET]');
  });
});

describe('ac-3: literal multi-pattern match → [redacted:NAME]', () => {
  it('a raw secret value present in output is replaced with [redacted:NAME] where NAME is the secret’s env-var name, not the value', async () => {
    const value = 'raw-secret-value-aaa';
    const scrubber = createScrubber({ entries: [entryFor('OPENAI_API_KEY', value)] });
    const { output } = await runScrubber(scrubber, [`key=${value}\n`]);
    expect(output).toBe('key=[redacted:OPENAI_API_KEY]\n');
    expect(output).not.toContain(value);
  });

  it('the base64 encoded variant of a secret (from encodedVariants) present in output is replaced with [redacted:NAME]', async () => {
    const value = 'base64-me-secret-value';
    const b64 = Buffer.from(value, 'utf8').toString('base64');
    const scrubber = createScrubber({ entries: [entryFor('SECRET', value)] });
    const { output } = await runScrubber(scrubber, [`encoded=${b64}\n`]);
    expect(output).toBe('encoded=[redacted:SECRET]\n');
    expect(output).not.toContain(b64);
  });

  it('matching is literal substring, not regex: a pattern containing regex metacharacters (e.g. a value with ‘.’, ‘*’, ‘(’) is matched as literal bytes and a non-identical near-string is left untouched', async () => {
    const value = 'a.b*c(d)e+f^g$h';
    const scrubber = createScrubber({ entries: [{ name: 'METACHARS', patterns: [value] }] });
    // A near-string where the metacharacters would match under regex semantics
    // (e.g. '.' matching any char) but is NOT byte-identical.
    const near = 'aXbYcZdAeBfCgDh';
    const { output } = await runScrubber(scrubber, [`exact=${value} near=${near}`]);
    expect(output).toBe('exact=[redacted:METACHARS] near=' + near);
  });

  it('multiple distinct patterns in one stream are each replaced with their own [redacted:NAME]; two adjacent occurrences of the same pattern are both replaced', async () => {
    const a = 'first-secret-value-aaa';
    const b = 'second-secret-value-bbb';
    const scrubber = createScrubber({
      entries: [entryFor('ALPHA', a), entryFor('BETA', b)],
    });
    const { output } = await runScrubber(scrubber, [`${a} ${b} ${a}${a}`]);
    expect(output).toBe('[redacted:ALPHA] [redacted:BETA] [redacted:ALPHA][redacted:ALPHA]');
  });

  it('the replacement token carries the secret NAME, never the secret value: the value’s characters do not appear anywhere in the scrubbed output', async () => {
    const value = 'never-leak-this-secret-zzz';
    const scrubber = createScrubber({ entries: [entryFor('DB_PASSWORD', value)] });
    const { output } = await runScrubber(scrubber, [`line1 ${value} line2\n`, `again ${value}\n`]);
    expect(output).not.toContain(value);
    expect(output).toContain('[redacted:DB_PASSWORD]');
  });
});

describe('ac-4: handle-canary warning', () => {
  // A handle string as it appears downstream: chaff:1:NAME:nonce.
  const handle: HandleEntry = { name: 'API_KEY', handle: 'chaff:1:API_KEY:0123456789ab' };

  it('when a handle string (chaff:1:NAME:nonce) appears in the child’s output, a canary warning naming the secret (NAME) is written to chaff’s own stderr sink', async () => {
    const warnings: string[] = [];
    const scrubber = createScrubber({
      entries: [],
      handles: [handle],
      onCanary: (name) => warnings.push(name),
    });
    await runScrubber(scrubber, [`leaked handle: ${handle.handle}\n`]);
    expect(warnings).toContain('API_KEY');
  });

  it('the same handle appearance writes an audit entry via the audit log (op identifies a canary/handle-leak; secretName is the handle’s NAME, never the value)', async () => {
    const audited: Array<{ op: string; secretName: string }> = [];
    const scrubber = createScrubber({
      entries: [],
      handles: [handle],
      onCanary: () => {},
      onAudit: (record) => audited.push(record),
    });
    await runScrubber(scrubber, [`${handle.handle}`]);
    expect(audited).toHaveLength(1);
    expect(audited[0]!.secretName).toBe('API_KEY');
    expect(audited[0]!.op).toMatch(/canary|handle/i);
  });

  it('the canary warning fires on the handle appearing in output; output bytes themselves are not corrupted by the warning path (handle text either passes through or is itself redacted, but the child’s surrounding bytes are intact)', async () => {
    const warnings: string[] = [];
    const scrubber = createScrubber({
      entries: [],
      handles: [handle],
      onCanary: (name) => warnings.push(name),
    });
    const { output } = await runScrubber(scrubber, [`before ${handle.handle} after`]);
    expect(warnings).toContain('API_KEY');
    // Surrounding innocent bytes are intact.
    expect(output.startsWith('before ')).toBe(true);
    expect(output.endsWith(' after')).toBe(true);
  });
});
