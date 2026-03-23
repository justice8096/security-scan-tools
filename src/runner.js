/**
 * Full scan runner — orchestrates all scanners and produces a unified report.
 */

import { scanOwaspLlm } from './scanners/owasp-llm.js';
import { auditDependencies } from './scanners/dependency-audit.js';
import { scanSastPatterns } from './scanners/sast-patterns.js';
import { detectSecrets } from './scanners/secrets-detector.js';
import { formatForCompliance } from './compliance-formatter.js';

/**
 * Run all security scanners against a repository.
 *
 * @param {string} repoPath - Path to repository
 * @param {object} [options]
 * @param {boolean} [options.owasp=true] - Run OWASP LLM Top 10 check
 * @param {boolean} [options.deps=true] - Run dependency audit
 * @param {boolean} [options.sast=true] - Run SAST patterns
 * @param {boolean} [options.secrets=true] - Run secrets detection
 * @param {boolean} [options.compliance=false] - Format output for compliance-config.json
 * @returns {object} Combined scan results
 */
export function runFullScan(repoPath, options = {}) {
  const {
    owasp = true,
    deps = true,
    sast = true,
    secrets = true,
    compliance = false
  } = options;

  const results = {
    scanDate: new Date().toISOString(),
    repoPath,
    scanners: {}
  };

  if (owasp) {
    console.error('[security-scan] Running OWASP LLM Top 10...');
    results.scanners.owaspLlm = scanOwaspLlm(repoPath);
  }

  if (deps) {
    console.error('[security-scan] Running dependency audit...');
    results.scanners.dependencies = auditDependencies(repoPath);
  }

  if (sast) {
    console.error('[security-scan] Running SAST patterns...');
    results.scanners.sast = scanSastPatterns(repoPath);
  }

  if (secrets) {
    console.error('[security-scan] Running secrets detection...');
    results.scanners.secrets = detectSecrets(repoPath);
  }

  // Aggregate severity counts
  results.aggregate = {
    critical: 0, high: 0, medium: 0, low: 0
  };
  for (const scanner of Object.values(results.scanners)) {
    if (scanner.bySeverity) {
      results.aggregate.critical += scanner.bySeverity.critical || 0;
      results.aggregate.high += scanner.bySeverity.high || 0;
      results.aggregate.medium += scanner.bySeverity.medium || 0;
      results.aggregate.low += scanner.bySeverity.low || 0;
    }
  }

  if (compliance) {
    results.complianceFields = formatForCompliance(results);
  }

  return results;
}
