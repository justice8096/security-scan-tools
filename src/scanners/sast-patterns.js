/**
 * Static Application Security Testing (SAST) Pattern Scanner
 *
 * Scans source code for common vulnerability patterns without requiring
 * external tools like semgrep. Covers CERT secure coding standards.
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import { walkFiles } from '../utils/file-walker.js';

/**
 * SAST rules covering CERT, CWE, and common vulnerability patterns.
 */
export const SAST_RULES = [
  // Injection
  {
    id: 'SAST-INJ-001',
    name: 'SQL Injection',
    cwe: 'CWE-89',
    cert: 'IDS00-J',
    severity: 'critical',
    patterns: [
      /(?:query|execute|raw)\s*\(\s*[`"'].*\$\{/gi,
      /(?:query|execute)\s*\(\s*["'].*\+\s*(?:req|input|param|user|body)/gi,
      /(?:query|execute)\s*\(\s*`[^`]*\$\{(?:req|input|param|user|body)/gi,
    ],
    description: 'String concatenation in SQL queries allows injection attacks',
    fix: 'Use parameterized queries or prepared statements'
  },
  {
    id: 'SAST-INJ-002',
    name: 'Command Injection',
    cwe: 'CWE-78',
    cert: 'IDS07-J',
    severity: 'critical',
    patterns: [
      /(?:exec|execSync|system)\s*\(\s*[`"'].*\$\{/gi,
      /(?:exec|execSync|system)\s*\(\s*["'].*\+\s*(?:req|input|param|user|body)/gi,
      /child_process.*exec\s*\(\s*(?!.*\[)/gi,
      /subprocess\.(?:call|run|Popen)\s*\(\s*(?:f["']|["'].*\+|.*format)/gi,
    ],
    description: 'Dynamic command construction enables OS command injection',
    fix: 'Use execFile/execFileSync with argument arrays instead of exec with string interpolation'
  },
  {
    id: 'SAST-INJ-003',
    name: 'XSS / Unsafe HTML',
    cwe: 'CWE-79',
    cert: 'IDS51-J',
    severity: 'high',
    patterns: [
      /innerHTML\s*=\s*(?!['"]<)/gi,
      /dangerouslySetInnerHTML/gi,
      /document\.write\s*\(/gi,
      /\.html\s*\(\s*(?:req|input|param|user|body|data|response)/gi,
    ],
    description: 'Inserting untrusted data as HTML enables cross-site scripting',
    fix: 'Use textContent, DOM APIs, or sanitization libraries (DOMPurify)'
  },
  {
    id: 'SAST-INJ-004',
    name: 'Path Traversal',
    cwe: 'CWE-22',
    cert: 'FIO16-J',
    severity: 'high',
    patterns: [
      /(?:readFile|writeFile|createReadStream|open)\s*\(.*(?:req\.|params\.|query\.|body\.)/gi,
      /path\.(?:join|resolve)\s*\(.*(?:req\.|params\.|query\.|body\.)/gi,
      /os\.path\.join\s*\(.*(?:request|input|param)/gi,
    ],
    description: 'User-controlled file paths enable directory traversal',
    fix: 'Validate and sanitize file paths. Use path.resolve and check against a base directory'
  },
  // Cryptography
  {
    id: 'SAST-CRY-001',
    name: 'Weak Cryptography',
    cwe: 'CWE-327',
    cert: 'MSC61-J',
    severity: 'high',
    patterns: [
      /createHash\s*\(\s*['"](?:md5|sha1)['"]\)/gi,
      /(?:hashlib\.)?(?:md5|sha1)\s*\(/gi,
      /\bDES\b|(?<![a-zA-Z])RC4(?![a-zA-Z])|\bBlowfish\b/g,
      /createCipher\s*\(\s*['"](?:des|rc4|aes-128-ecb)/gi,
    ],
    description: 'Weak hash algorithms or ciphers that are cryptographically broken',
    fix: 'Use SHA-256+ for hashing, AES-256-GCM for encryption'
  },
  {
    id: 'SAST-CRY-002',
    name: 'Hardcoded Secrets',
    cwe: 'CWE-798',
    cert: 'MSC03-J',
    severity: 'critical',
    patterns: [
      /(?:password|passwd|secret|api_key|apikey|token|auth)\s*[:=]\s*["'][^"']{8,}/gi,
      /(?:PRIVATE[\s_]KEY|BEGIN RSA)/gi,
      /(?:sk-|pk_live_|sk_live_|ghp_|gho_|github_pat_)/gi,
    ],
    description: 'Credentials hardcoded in source code',
    fix: 'Use environment variables or secret management systems'
  },
  // Authentication/Authorization
  {
    id: 'SAST-AUTH-001',
    name: 'Missing Authentication',
    cwe: 'CWE-306',
    cert: 'SEC00-J',
    severity: 'high',
    patterns: [
      /app\.(?:get|post|put|delete|patch)\s*\(\s*['"][^'"]*(?:admin|user|api|internal)[^'"]*['"]\s*,\s*(?:async\s+)?\(?(?:req|ctx)/gi,
    ],
    description: 'API endpoints without authentication middleware',
    fix: 'Add authentication middleware to protected routes'
  },
  // Error Handling
  {
    id: 'SAST-ERR-001',
    name: 'Information Exposure in Errors',
    cwe: 'CWE-209',
    cert: 'ERR01-J',
    severity: 'medium',
    patterns: [
      /catch\s*\(.*\)\s*\{[^}]*res\.(?:send|json)\s*\(.*(?:err|error|e)\.(?:message|stack)/gi,
      /\.status\s*\(\s*500\s*\).*(?:stack|trace|message)/gi,
    ],
    description: 'Stack traces or detailed errors exposed to users',
    fix: 'Return generic error messages. Log details server-side only'
  },
  // Unsafe Deserialization
  {
    id: 'SAST-DES-001',
    name: 'Unsafe Deserialization',
    cwe: 'CWE-502',
    cert: 'SER12-J',
    severity: 'critical',
    patterns: [
      /eval\s*\(\s*(?:req|input|body|data|params|user)/gi,
      /new\s+Function\s*\(\s*(?:req|input|body|data)/gi,
      /pickle\.loads?\s*\(\s*(?:request|input|data|user)/gi,
      /yaml\.(?:load|unsafe_load)\s*\(/gi,
    ],
    description: 'Deserializing untrusted data can lead to remote code execution',
    fix: 'Validate and sanitize before deserialization. Use safe parsers (yaml.safe_load)'
  },
  // Logging
  {
    id: 'SAST-LOG-001',
    name: 'Sensitive Data in Logs',
    cwe: 'CWE-532',
    cert: 'FIO13-J',
    severity: 'medium',
    patterns: [
      /(?:console\.log|logger?\.\w+|print)\s*\(.*(?:password|secret|token|api[\s_]?key|ssn|credit)/gi,
    ],
    description: 'Logging sensitive information creates a data leak vector',
    fix: 'Redact sensitive fields before logging'
  }
];

/**
 * Scan source files for SAST vulnerability patterns.
 *
 * @param {string} repoPath - Path to repository
 * @param {object} [options]
 * @param {string[]} [options.exclude] - Directories to exclude
 * @param {string[]} [options.extensions] - File extensions to scan
 * @param {string[]} [options.ruleIds] - Only run specific rules (by ID)
 * @returns {object} Scan results
 */
export function scanSastPatterns(repoPath, options = {}) {
  const {
    exclude = ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'coverage'],
    extensions = ['.js', '.ts', '.py', '.jsx', '.tsx', '.mjs', '.cjs', '.java'],
    ruleIds = null
  } = options;

  const resolved = resolve(repoPath);
  const files = walkFiles(resolved, { exclude, extensions });

  const rulesToRun = ruleIds
    ? SAST_RULES.filter(r => ruleIds.includes(r.id))
    : SAST_RULES;

  const findings = [];

  for (const filePath of files) {
    let content;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch { continue; }

    const lines = content.split('\n');
    const relPath = filePath.replace(resolved, '.').replace(/\\/g, '/');

    for (const rule of rulesToRun) {
      for (const pattern of rule.patterns) {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const beforeMatch = content.substring(0, match.index);
          const lineNum = beforeMatch.split('\n').length;
          const lineContent = lines[lineNum - 1]?.trim() || '';
          const isComment = lineContent.startsWith('//') || lineContent.startsWith('#') || lineContent.startsWith('*') || lineContent.startsWith('"""');

          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            cwe: rule.cwe,
            cert: rule.cert,
            severity: rule.severity,
            file: relPath,
            line: lineNum,
            matchedText: match[0].substring(0, 100),
            lineContent: lineContent.substring(0, 200),
            isComment,
            description: rule.description,
            fix: rule.fix
          });

          if (match.index === pattern.lastIndex) pattern.lastIndex++;
        }
      }
    }
  }

  return {
    scanner: 'sast-patterns',
    repoPath: resolved,
    timestamp: new Date().toISOString(),
    rulesChecked: rulesToRun.length,
    totalFindings: findings.length,
    codeFindings: findings.filter(f => !f.isComment).length,
    bySeverity: {
      critical: findings.filter(f => f.severity === 'critical' && !f.isComment).length,
      high: findings.filter(f => f.severity === 'high' && !f.isComment).length,
      medium: findings.filter(f => f.severity === 'medium' && !f.isComment).length
    },
    findings
  };
}
