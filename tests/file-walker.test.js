import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { walkFiles } from '../src/utils/file-walker.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import os from 'os';

describe('walkFiles', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = join(os.tmpdir(), 'walker-test-' + Date.now());
    mkdirSync(join(tmpDir, 'src', 'lib'), { recursive: true });
    mkdirSync(join(tmpDir, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(join(tmpDir, 'src', 'index.js'), '');
    writeFileSync(join(tmpDir, 'src', 'lib', 'util.js'), '');
    writeFileSync(join(tmpDir, 'src', 'style.css'), '');
    writeFileSync(join(tmpDir, 'node_modules', 'pkg', 'index.js'), '');
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('finds files recursively', () => {
    const files = walkFiles(tmpDir, { exclude: [], extensions: ['.js'] });
    expect(files.length).toBeGreaterThanOrEqual(3);
  });

  it('filters by extension', () => {
    const files = walkFiles(tmpDir, { exclude: ['node_modules'], extensions: ['.js'] });
    expect(files.every(f => f.endsWith('.js'))).toBe(true);
    expect(files.some(f => f.includes('style.css'))).toBe(false);
  });

  it('excludes directories', () => {
    const files = walkFiles(tmpDir, { exclude: ['node_modules'], extensions: ['.js'] });
    expect(files.some(f => f.includes('node_modules'))).toBe(false);
  });

  it('returns empty for empty dir', () => {
    const emptyDir = join(tmpDir, 'empty');
    mkdirSync(emptyDir);
    const files = walkFiles(emptyDir, { extensions: ['.js'] });
    expect(files).toHaveLength(0);
  });
});
