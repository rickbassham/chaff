import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { type LevelConfig } from '../../src/config.js';

/**
 * Write `config` as JSON into the chaff config directory `dir` (which must
 * already exist). Test-only helper for seeding config on disk without pinning
 * the on-disk format into production code or the public library surface; the
 * config loaders ({@link loadUserConfig}, {@link loadFolderConfig}) read it
 * back through their public API.
 */
export function writeConfig(dir: string, config: Partial<LevelConfig>): void {
  writeFileSync(join(dir, 'config.json'), JSON.stringify(config), 'utf8');
}
