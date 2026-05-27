/**
 * DAR-1108 — README intra-repo link/anchor resolution.
 *
 * The README documents the threat model and known gaps by pointing at PLAN.md
 * sections (e.g. "Known gaps", "Layer A — default-deny harness env", the four
 * design decisions). Those targets are headings in another file, so a rename or
 * reword silently rots the link. This test walks every intra-repo markdown link
 * in README.md and asserts (a) the target file exists and (b) any `#anchor`
 * resolves to an actual heading in that file — GitHub's slugging rules — so link
 * rot fails CI rather than shipping.
 *
 * Out of scope by design: external `http(s)://` links (network, not our repo)
 * and the prose-correctness of the surrounding text (graded by review, not a
 * substring grep — see the contract's explicit non-goals).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const README = join(REPO_ROOT, 'README.md');

/** A markdown link extracted from a file: its raw target and where it came from. */
interface Link {
  /** The link target as written, e.g. `./PLAN.md#known-gaps` or `#threat-model`. */
  target: string;
  /** The file the link lives in (for resolving same-file anchors / relative paths). */
  sourceFile: string;
}

/** Extract every `[text](target)` inline-link target from markdown source. */
function extractLinks(markdown: string, sourceFile: string): Link[] {
  const links: Link[] = [];
  // Inline links: [text](target). Targets may carry an #anchor. We deliberately
  // ignore link *titles* (the optional "..." after the URL) — none are used here.
  const re = /\[[^\]]*\]\(([^)\s]+)\)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(markdown)) !== null) {
    const target = match[1];
    if (target !== undefined) {
      links.push({ target, sourceFile });
    }
  }
  return links;
}

/** Is this an external link we should not try to resolve on disk? */
function isExternal(target: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(target) || target.startsWith('mailto:');
}

/**
 * Slugify a heading the way GitHub does: lowercase, strip anything that is not a
 * word char / space / hyphen, then turn spaces into hyphens. Good enough for the
 * ASCII headings this repo uses (em dashes and other punctuation are dropped).
 */
function slugify(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s/g, '-');
}

/** Collect the set of GitHub heading-anchor slugs present in a markdown file. */
function headingSlugs(markdown: string): Set<string> {
  const slugs = new Set<string>();
  for (const line of markdown.split('\n')) {
    const m = /^#{1,6}\s+(.*?)\s*#*$/.exec(line);
    if (m && m[1] !== undefined) {
      slugs.add(slugify(m[1]));
    }
  }
  return slugs;
}

describe('README intra-repo links', () => {
  const readmeSource = readFileSync(README, 'utf8');
  const links = extractLinks(readmeSource, README).filter((l) => !isExternal(l.target));

  it('finds at least one intra-repo link (guards against the regex silently matching nothing)', () => {
    expect(links.length).toBeGreaterThan(0);
  });

  it.each(links.map((l) => [l.target, l]))(
    'resolves intra-repo link %s to an existing file/heading',
    (_target, link) => {
      const [pathPart = '', anchor] = link.target.split('#');

      // Resolve the target file: an empty path means a same-file anchor.
      const targetFile =
        pathPart === '' ? link.sourceFile : resolve(dirname(link.sourceFile), pathPart);

      expect(existsSync(targetFile), `link target file missing: ${link.target}`).toBe(true);

      if (anchor !== undefined && anchor !== '') {
        const targetSource = readFileSync(targetFile, 'utf8');
        const slugs = headingSlugs(targetSource);
        expect(slugs.has(anchor), `anchor #${anchor} not found as a heading in ${targetFile}`).toBe(
          true,
        );
      }
    },
  );
});
