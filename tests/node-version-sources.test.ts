/**
 * DAR-1152 — Node version sources of truth: deliberate floor-vs-latest split.
 *
 * The repo has two Node-version sources that are *intentionally* different:
 *
 *   - `package.json` `engines.node` = `>=22` — the supported floor (CI tests 22 + 24).
 *   - `.nvmrc` = `24` — the recommended dev/latest version (`nvm use` lands here).
 *
 * The policy (DAR-1152, 2026-05-27) is that these MUST stay different and the
 * README must frame them as a deliberate split rather than a contradiction.
 *
 * These tests lock down the two failure modes a mechanical check can catch:
 *   1. Either file silently drifting off its policy value.
 *   2. The README citing a Node version that no longer matches its source file
 *      (citation drift — a file bumped without updating the README).
 *
 * The prose-correctness of the floor-vs-latest *explanation* is graded by review
 * (the contract's ac-2 manual test), not asserted here — a substring grep on
 * prose does not catch a real failure mode.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const README = join(REPO_ROOT, 'README.md');
const PACKAGE_JSON = join(REPO_ROOT, 'package.json');
const NVMRC = join(REPO_ROOT, '.nvmrc');

/** The `engines.node` constraint as written in package.json. */
function enginesNode(): string {
  const pkg = JSON.parse(readFileSync(PACKAGE_JSON, 'utf8'));
  return pkg.engines.node;
}

/** The trimmed `.nvmrc` contents (the recommended dev/latest version). */
function nvmrcVersion(): string {
  return readFileSync(NVMRC, 'utf8').trim();
}

describe('Node version sources of truth (DAR-1152)', () => {
  it('package.json `engines.node` parses to exactly `>=22`', () => {
    expect(enginesNode()).toBe('>=22');
  });

  it('`.nvmrc` trimmed contents equal exactly `24`', () => {
    expect(nvmrcVersion()).toBe('24');
  });

  it('README cites both Node versions accurately (citation-drift check)', () => {
    const readme = readFileSync(README, 'utf8');

    // The floor's bare version number, e.g. `22` from `>=22`.
    const floorMatch = /(\d+)/.exec(enginesNode());
    expect(floorMatch, `could not extract a version number from engines.node`).not.toBeNull();
    const floor = floorMatch![1]!;
    const latest = nvmrcVersion();

    // Locate the Development section: from its heading to the next top-level
    // `## ` heading or end of file. The Node-version citation lives here per
    // the AC. (JS regex has no `\Z`; `(?![\s\S])` is the end-of-input anchor.)
    const devMatch = /^## Development\b[\s\S]*?(?=^## |(?![\s\S]))/m.exec(readme);
    expect(devMatch, 'README has no `## Development` section').not.toBeNull();
    const devSection = devMatch![0];

    // Both source numbers must appear in the Development section. If a file is
    // bumped without updating the README, the stale number no longer matches
    // and this fails — catching the broken-citation failure mode.
    expect(
      devSection.includes(floor),
      `Development section does not cite the engines.node floor (${floor})`,
    ).toBe(true);
    expect(
      devSection.includes(latest),
      `Development section does not cite the .nvmrc dev/latest version (${latest})`,
    ).toBe(true);
  });
});
