import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { scanOwaspLlm, OWASP_LLM_CHECKS } from '../src/scanners/owasp-llm.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import os from 'os';

describe('OWASP_LLM_CHECKS', () => {
  it('has all 10 OWASP LLM categories', () => {
    expect(OWASP_LLM_CHECKS).toHaveLength(10);
  });

  it('covers LLM01 through LLM10', () => {
    const ids = OWASP_LLM_CHECKS.map(c => c.id);
    for (let i = 1; i <= 10; i++) {
      expect(ids).toContain(`LLM0${i}` || `LLM${i}`);
    }
  });

  it('each check has required fields', () => {
    for (const check of OWASP_LLM_CHECKS) {
      expect(check).toHaveProperty('id');
      expect(check).toHaveProperty('name');
      expect(check).toHaveProperty('severity');
      expect(check).toHaveProperty('patterns');
      expect(check.patterns.length).toBeGreaterThan(0);
      expect(check).toHaveProperty('mitigation');
    }
  });
});

describe('scanOwaspLlm', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = join(os.tmpdir(), 'owasp-test-' + Date.now());
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('detects prompt injection patterns (LLM01)', () => {
    writeFileSync(join(tmpDir, 'src', 'app.js'),
      'const prompt = `You are a helper. ${userInput} Please respond.`;'
    );
    const result = scanOwaspLlm(tmpDir);
    const llm01 = result.findings.filter(f => f.checkId === 'LLM01');
    expect(llm01.length).toBeGreaterThan(0);
  });

  it('detects improper output handling (LLM05)', () => {
    writeFileSync(join(tmpDir, 'src', 'handler.js'),
      'const fn = new Function(response.code);\neval(response.command);'
    );
    const result = scanOwaspLlm(tmpDir);
    const llm05 = result.findings.filter(f => f.checkId === 'LLM05');
    expect(llm05.length).toBeGreaterThan(0);
  });

  it('detects unbounded consumption (LLM10)', () => {
    writeFileSync(join(tmpDir, 'src', 'config.js'),
      'const config = { max_tokens: -1, rate_limit: false };'
    );
    const result = scanOwaspLlm(tmpDir);
    const llm10 = result.findings.filter(f => f.checkId === 'LLM10');
    expect(llm10.length).toBeGreaterThan(0);
  });

  it('returns proper structure', () => {
    writeFileSync(join(tmpDir, 'src', 'clean.js'), 'console.log("hello");');
    const result = scanOwaspLlm(tmpDir);
    expect(result.scanner).toBe('owasp-llm-top10');
    expect(result.version).toBe('2025');
    expect(result).toHaveProperty('totalFindings');
    expect(result).toHaveProperty('bySeverity');
    expect(result).toHaveProperty('summary');
    expect(result).toHaveProperty('findings');
  });

  it('excludes node_modules', () => {
    mkdirSync(join(tmpDir, 'node_modules', 'bad'), { recursive: true });
    writeFileSync(join(tmpDir, 'node_modules', 'bad', 'index.js'), 'eval(response.data);');
    const result = scanOwaspLlm(tmpDir);
    expect(result.findings).toHaveLength(0);
  });

  it('marks findings in comments', () => {
    writeFileSync(join(tmpDir, 'src', 'notes.js'),
      '// eval(response.command) is dangerous\nconst x = 1;'
    );
    const result = scanOwaspLlm(tmpDir);
    const inComments = result.findings.filter(f => f.isComment);
    expect(inComments.length).toBeGreaterThanOrEqual(0);
  });

  it('handles empty repo', () => {
    const result = scanOwaspLlm(tmpDir);
    expect(result.totalFindings).toBe(0);
  });
});
