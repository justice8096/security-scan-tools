import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { detectEcosystems } from '../src/scanners/dependency-audit.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import os from 'os';

describe('detectEcosystems', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = join(os.tmpdir(), 'dep-test-' + Date.now());
    mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('detects npm from package.json', () => {
    writeFileSync(join(tmpDir, 'package.json'), '{}');
    expect(detectEcosystems(tmpDir)).toContain('npm');
  });

  it('detects pip from requirements.txt', () => {
    writeFileSync(join(tmpDir, 'requirements.txt'), 'flask==2.0');
    expect(detectEcosystems(tmpDir)).toContain('pip');
  });

  it('detects pip from pyproject.toml', () => {
    writeFileSync(join(tmpDir, 'pyproject.toml'), '[project]');
    expect(detectEcosystems(tmpDir)).toContain('pip');
  });

  it('detects go from go.sum', () => {
    writeFileSync(join(tmpDir, 'go.sum'), '');
    expect(detectEcosystems(tmpDir)).toContain('go');
  });

  it('detects cargo from Cargo.lock', () => {
    writeFileSync(join(tmpDir, 'Cargo.lock'), '');
    expect(detectEcosystems(tmpDir)).toContain('cargo');
  });

  it('returns empty for empty dir', () => {
    expect(detectEcosystems(tmpDir)).toHaveLength(0);
  });

  it('detects multiple ecosystems', () => {
    writeFileSync(join(tmpDir, 'package.json'), '{}');
    writeFileSync(join(tmpDir, 'requirements.txt'), '');
    const ecosystems = detectEcosystems(tmpDir);
    expect(ecosystems).toContain('npm');
    expect(ecosystems).toContain('pip');
  });
});
