import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { detectSecrets, SECRET_PATTERNS } from '../src/scanners/secrets-detector.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import os from 'os';

describe('SECRET_PATTERNS', () => {
  it('covers major providers', () => {
    const names = SECRET_PATTERNS.map(p => p.name);
    expect(names.some(n => n.includes('AWS'))).toBe(true);
    expect(names.some(n => n.includes('GitHub'))).toBe(true);
    expect(names.some(n => n.includes('OpenAI'))).toBe(true);
    expect(names.some(n => n.includes('Private Key'))).toBe(true);
  });
});

describe('detectSecrets', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = join(os.tmpdir(), 'secrets-test-' + Date.now());
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('detects AWS access keys', () => {
    writeFileSync(join(tmpDir, 'src', 'config.js'),
      'const KEY = "AKIAIOSFODNN7EXAMPLE";'
    );
    const result = detectSecrets(tmpDir);
    expect(result.findings.some(f => f.secretId === 'SEC-AWS-001')).toBe(true);
  });

  it('detects GitHub tokens', () => {
    writeFileSync(join(tmpDir, 'src', 'auth.js'),
      'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno";'
    );
    const result = detectSecrets(tmpDir);
    expect(result.findings.some(f => f.secretId === 'SEC-GH-001')).toBe(true);
  });

  it('detects private keys', () => {
    writeFileSync(join(tmpDir, 'src', 'key.pem'),
      '-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...'
    );
    const result = detectSecrets(tmpDir);
    expect(result.findings.some(f => f.secretId === 'SEC-PK-001')).toBe(true);
  });

  it('detects database connection strings', () => {
    writeFileSync(join(tmpDir, 'src', 'db.js'),
      'const url = "postgres://admin:secretpass@db.example.com:5432/mydb";'
    );
    const result = detectSecrets(tmpDir);
    expect(result.findings.some(f => f.secretId === 'SEC-CONN-001')).toBe(true);
  });

  it('masks detected secrets in output', () => {
    writeFileSync(join(tmpDir, 'src', 'config.js'),
      'const KEY = "AKIAIOSFODNN7EXAMPLE";'
    );
    const result = detectSecrets(tmpDir);
    for (const finding of result.findings) {
      expect(finding.maskedValue).toContain('...');
      expect(finding).not.toHaveProperty('fullValue');
    }
  });

  it('skips .example files', () => {
    writeFileSync(join(tmpDir, 'src', '.env.example'),
      'API_KEY=AKIAIOSFODNN7EXAMPLE'
    );
    const result = detectSecrets(tmpDir);
    expect(result.findings).toHaveLength(0);
  });

  it('returns proper structure', () => {
    const result = detectSecrets(tmpDir);
    expect(result.scanner).toBe('secrets-detector');
    expect(result).toHaveProperty('bySeverity');
    expect(result).toHaveProperty('findings');
  });
});
