/**
 * Recursive file walker with exclusion support.
 */
import { readdirSync, statSync } from 'fs';
import { join, extname, basename } from 'path';

/**
 * Walk a directory tree and return matching files.
 *
 * @param {string} dir - Directory to walk
 * @param {object} options
 * @param {string[]} options.exclude - Directory names to skip
 * @param {string[]} options.extensions - File extensions to include
 * @returns {string[]} Array of file paths
 */
export function walkFiles(dir, options = {}) {
  const { exclude = [], extensions = [] } = options;
  const results = [];

  function walk(currentDir) {
    let entries;
    try {
      entries = readdirSync(currentDir);
    } catch { return; }

    for (const entry of entries) {
      if (exclude.includes(entry) || entry.startsWith('.')) continue;

      const fullPath = join(currentDir, entry);
      let stat;
      try {
        stat = statSync(fullPath);
      } catch { continue; }

      if (stat.isDirectory()) {
        walk(fullPath);
      } else if (stat.isFile()) {
        const ext = extname(entry);
        if (extensions.length === 0 || extensions.includes(ext)) {
          results.push(fullPath);
        }
      }
    }
  }

  walk(dir);
  return results;
}
