/**
 * Secrets and Credential Detector
 *
 * Scans files for accidentally committed secrets, API keys, and credentials.
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import { walkFiles } from '../utils/file-walker.js';

export const SECRET_PATTERNS = [
  { id: 'SEC-AWS-001', name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { id: 'SEC-AWS-002', name: 'AWS Secret Key', pattern: /(?:aws)?[\s_]?secret[\s_]?(?:access)?[\s_]?key[\s"':=]*\s*[A-Za-z0-9/+=]{40}/gi, severity: 'critical' },
  { id: 'SEC-GH-001', name: 'GitHub Token', pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g, severity: 'critical' },
  { id: 'SEC-GH-002', name: 'GitHub Fine-Grained PAT', pattern: /github_pat_[A-Za-z0-9_]{22,}/g, severity: 'critical' },
  { id: 'SEC-OPENAI-001', name: 'OpenAI API Key', pattern: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, severity: 'critical' },
  { id: 'SEC-ANTHROPIC-001', name: 'Anthropic API Key', pattern: /sk-ant-[A-Za-z0-9_-]{40,}/g, severity: 'critical' },
  { id: 'SEC-STRIPE-001', name: 'Stripe Key', pattern: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}/g, severity: 'critical' },
  { id: 'SEC-SLACK-001', name: 'Slack Token', pattern: /xox[bpors]-[A-Za-z0-9-]{10,}/g, severity: 'high' },
  { id: 'SEC-PK-001', name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
  { id: 'SEC-JWT-001', name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'high' },
  { id: 'SEC-GCP-001', name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: 'high' },
  { id: 'SEC-NPM-001', name: 'npm Token', pattern: /npm_[A-Za-z0-9]{36}/g, severity: 'critical' },
  { id: 'SEC-PYPI-001', name: 'PyPI Token', pattern: /pypi-[A-Za-z0-9_-]{50,}/g, severity: 'critical' },
  { id: 'SEC-GENERIC-001', name: 'Generic High-Entropy Secret', pattern: /(?:secret|password|passwd|api_key|apikey|token|auth_token|access_token)[\s"':=]+[A-Za-z0-9+/=_-]{20,}/gi, severity: 'medium' },
  { id: 'SEC-CONN-001', name: 'Database Connection String', pattern: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s"']+:[^\s"']+@/gi, severity: 'critical' },
];

/**
 * Scan files for secrets and credentials.
 *
 * @param {string} repoPath - Path to repository
 * @param {object} [options]
 * @param {string[]} [options.exclude] - Directories to exclude
 * @param {string[]} [options.extensions] - File extensions to scan
 * @param {boolean} [options.includeTests] - Include test files (default: false)
 * @returns {object} Scan results
 */
export function detectSecrets(repoPath, options = {}) {
  const {
    exclude = ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv'],
    extensions = ['.js', '.ts', '.py', '.jsx', '.tsx', '.json', '.yaml', '.yml', '.env', '.cfg', '.conf', '.ini', '.properties', '.toml'],
    includeTests = false
  } = options;

  const resolved = resolve(repoPath);
  const allExclude = includeTests ? exclude : [...exclude, 'test', 'tests', '__tests__', 'spec'];
  const files = walkFiles(resolved, { exclude: allExclude, extensions });

  const findings = [];

  for (const filePath of files) {
    let content;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch { continue; }

    // Skip binary files and very large files
    if (content.includes('\0') || content.length > 1024 * 1024) continue;

    const lines = content.split('\n');
    const relPath = filePath.replace(resolved, '.').replace(/\\/g, '/');

    // Skip example/template files
    if (relPath.includes('.example') || relPath.includes('.template') || relPath.includes('.sample')) continue;

    for (const secret of SECRET_PATTERNS) {
      secret.pattern.lastIndex = 0;
      let match;
      while ((match = secret.pattern.exec(content)) !== null) {
        const beforeMatch = content.substring(0, match.index);
        const lineNum = beforeMatch.split('\n').length;
        const lineContent = lines[lineNum - 1]?.trim() || '';

        // Mask the secret value
        const masked = match[0].substring(0, 8) + '...' + match[0].substring(match[0].length - 4);

        findings.push({
          secretId: secret.id,
          secretName: secret.name,
          severity: secret.severity,
          file: relPath,
          line: lineNum,
          maskedValue: masked,
          linePreview: lineContent.substring(0, 100).replace(match[0], '[REDACTED]')
        });

        if (match.index === secret.pattern.lastIndex) secret.pattern.lastIndex++;
      }
    }
  }

  return {
    scanner: 'secrets-detector',
    repoPath: resolved,
    timestamp: new Date().toISOString(),
    totalFindings: findings.length,
    bySeverity: {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length
    },
    findings
  };
}
