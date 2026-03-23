/**
 * security-scan-tools — Unified security scanning with compliance integration.
 *
 * Wraps multiple security scanners behind a single API:
 * - OWASP LLM Top 10 pattern detection
 * - Dependency vulnerability auditing (npm audit, pip-audit, osv-scanner)
 * - Static analysis patterns (secrets, injection, unsafe code)
 * - Secrets/credential detection
 *
 * Outputs JSON compatible with compliance-config.json (Templates 15 + 23).
 */

export { scanOwaspLlm, OWASP_LLM_CHECKS } from './scanners/owasp-llm.js';
export { auditDependencies } from './scanners/dependency-audit.js';
export { scanSastPatterns, SAST_RULES } from './scanners/sast-patterns.js';
export { detectSecrets, SECRET_PATTERNS } from './scanners/secrets-detector.js';
export { runFullScan } from './runner.js';
export { formatForCompliance } from './compliance-formatter.js';
