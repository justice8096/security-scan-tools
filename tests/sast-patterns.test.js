import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { scanSastPatterns, SAST_RULES } from '../src/scanners/sast-patterns.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import os from 'os';

describe('SAST_RULES', () => {
  it('has rules for major categories', () => {
    const ids = SAST_RULES.map(r => r.id);
    expect(ids.some(id => id.includes('INJ'))).toBe(true);
    expect(ids.some(id => id.includes('CRY'))).toBe(true);
    expect(ids.some(id => id.includes('AUTH'))).toBe(true);
  });

  it('each rule has CWE reference', () => {
    for (const rule of SAST_RULES) {
      expect(rule.cwe).toMatch(/^CWE-\d+$/);
    }
  });

  it('each rule has CERT reference', () => {
    for (const rule of SAST_RULES) {
      expect(rule.cert).toBeTruthy();
    }
  });
});

describe('scanSastPatterns', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = join(os.tmpdir(), 'sast-test-' + Date.now());
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('detects SQL injection', () => {
    writeFileSync(join(tmpDir, 'src', 'db.js'),
      'db.query("SELECT * FROM users WHERE id = " + req.params.id);'
    );
    const result = scanSastPatterns(tmpDir);
    const sqli = result.findings.filter(f => f.ruleId === 'SAST-INJ-001');
    expect(sqli.length).toBeGreaterThan(0);
  });

  it('detects command injection', () => {
    writeFileSync(join(tmpDir, 'src', 'cmd.js'),
      'child_process.exec("ls " + req.body.path);'
    );
    const result = scanSastPatterns(tmpDir);
    const cmdi = result.findings.filter(f => f.ruleId === 'SAST-INJ-002');
    expect(cmdi.length).toBeGreaterThan(0);
  });

  it('detects XSS via innerHTML', () => {
    writeFileSync(join(tmpDir, 'src', 'view.js'),
      'element.innerHTML = response.data;'
    );
    const result = scanSastPatterns(tmpDir);
    const xss = result.findings.filter(f => f.ruleId === 'SAST-INJ-003');
    expect(xss.length).toBeGreaterThan(0);
  });

  it('detects weak cryptography', () => {
    writeFileSync(join(tmpDir, 'src', 'hash.js'),
      "const hash = crypto.createHash('md5').update(data).digest('hex');"
    );
    const result = scanSastPatterns(tmpDir);
    const weak = result.findings.filter(f => f.ruleId === 'SAST-CRY-001');
    expect(weak.length).toBeGreaterThan(0);
  });

  it('detects unsafe deserialization', () => {
    writeFileSync(join(tmpDir, 'src', 'parse.py'),
      'result = yaml.load(user_data)'
    );
    const result = scanSastPatterns(tmpDir);
    const deser = result.findings.filter(f => f.ruleId === 'SAST-DES-001');
    expect(deser.length).toBeGreaterThan(0);
  });

  it('filters by rule IDs', () => {
    writeFileSync(join(tmpDir, 'src', 'mixed.js'),
      "element.innerHTML = data;\ncrypto.createHash('md5');"
    );
    const result = scanSastPatterns(tmpDir, { ruleIds: ['SAST-INJ-003'] });
    expect(result.findings.every(f => f.ruleId === 'SAST-INJ-003')).toBe(true);
  });

  it('returns proper structure', () => {
    writeFileSync(join(tmpDir, 'src', 'clean.js'), 'const x = 1;');
    const result = scanSastPatterns(tmpDir);
    expect(result.scanner).toBe('sast-patterns');
    expect(result).toHaveProperty('rulesChecked');
    expect(result).toHaveProperty('bySeverity');
  });
});
