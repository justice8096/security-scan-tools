/**
 * Dependency Vulnerability Scanner
 *
 * Wraps npm audit, pip-audit, and osv-scanner to find CVEs in project dependencies.
 * Falls back gracefully when tools aren't installed.
 */

import { execFileSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join, resolve } from 'path';

/**
 * Detect which package ecosystems are present in a project.
 * @param {string} repoPath
 * @returns {string[]} Array of ecosystem names
 */
export function detectEcosystems(repoPath) {
  const ecosystems = [];
  if (existsSync(join(repoPath, 'package-lock.json')) || existsSync(join(repoPath, 'package.json'))) {
    ecosystems.push('npm');
  }
  if (existsSync(join(repoPath, 'yarn.lock'))) ecosystems.push('yarn');
  if (existsSync(join(repoPath, 'pnpm-lock.yaml'))) ecosystems.push('pnpm');
  if (existsSync(join(repoPath, 'requirements.txt')) || existsSync(join(repoPath, 'pyproject.toml')) || existsSync(join(repoPath, 'Pipfile.lock'))) {
    ecosystems.push('pip');
  }
  if (existsSync(join(repoPath, 'go.sum'))) ecosystems.push('go');
  if (existsSync(join(repoPath, 'Cargo.lock'))) ecosystems.push('cargo');
  if (existsSync(join(repoPath, 'composer.lock'))) ecosystems.push('composer');
  if (existsSync(join(repoPath, 'Gemfile.lock'))) ecosystems.push('ruby');
  return ecosystems;
}

/**
 * Check if a CLI tool is available.
 * @param {string} command
 * @returns {boolean}
 */
function isToolAvailable(command) {
  try {
    execFileSync(command, ['--version'], { stdio: 'pipe', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Run npm audit and parse results.
 * @param {string} repoPath
 * @returns {object}
 */
function runNpmAudit(repoPath) {
  try {
    const output = execFileSync('npm', ['audit', '--json'], {
      cwd: repoPath, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 60000
    });
    const report = JSON.parse(output);
    return {
      tool: 'npm-audit',
      success: true,
      vulnerabilities: report.metadata?.vulnerabilities || report.vulnerabilities || {},
      advisories: Object.values(report.advisories || {}).map(a => ({
        id: a.github_advisory_id || a.id,
        title: a.title,
        severity: a.severity,
        module: a.module_name,
        range: a.vulnerable_versions,
        recommendation: a.recommendation,
        url: a.url
      }))
    };
  } catch (err) {
    // npm audit exits non-zero when vulnerabilities found — still valid JSON
    try {
      const report = JSON.parse(err.stdout || '{}');
      return {
        tool: 'npm-audit',
        success: true,
        vulnerabilities: report.metadata?.vulnerabilities || {},
        advisories: Object.values(report.advisories || report.vulnerabilities || {}).map(a => ({
          id: a.github_advisory_id || a.id || a.name,
          title: a.title || a.name,
          severity: a.severity,
          module: a.module_name || a.name,
          range: a.vulnerable_versions || a.range,
          url: a.url
        }))
      };
    } catch {
      return { tool: 'npm-audit', success: false, error: err.message?.split('\n')[0] };
    }
  }
}

/**
 * Run pip-audit and parse results.
 * @param {string} repoPath
 * @returns {object}
 */
function runPipAudit(repoPath) {
  if (!isToolAvailable('pip-audit')) {
    return { tool: 'pip-audit', success: false, error: 'pip-audit not installed (pip install pip-audit)' };
  }
  try {
    const output = execFileSync('pip-audit', ['--format', 'json', '--desc'], {
      cwd: repoPath, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 120000
    });
    const results = JSON.parse(output);
    return {
      tool: 'pip-audit',
      success: true,
      vulnerabilities: results.map(v => ({
        id: v.id,
        package: v.name,
        installed: v.version,
        fixedIn: v.fix_versions?.join(', '),
        description: v.description
      }))
    };
  } catch (err) {
    try {
      const results = JSON.parse(err.stdout || '[]');
      return { tool: 'pip-audit', success: true, vulnerabilities: results };
    } catch {
      return { tool: 'pip-audit', success: false, error: err.message?.split('\n')[0] };
    }
  }
}

/**
 * Run osv-scanner (Google's open-source vulnerability scanner).
 * @param {string} repoPath
 * @returns {object}
 */
function runOsvScanner(repoPath) {
  if (!isToolAvailable('osv-scanner')) {
    return { tool: 'osv-scanner', success: false, error: 'osv-scanner not installed (https://google.github.io/osv-scanner/)' };
  }
  try {
    const output = execFileSync('osv-scanner', ['--json', '-r', repoPath], {
      encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 120000
    });
    const report = JSON.parse(output);
    return {
      tool: 'osv-scanner',
      success: true,
      results: (report.results || []).map(r => ({
        source: r.source?.path,
        packages: (r.packages || []).map(p => ({
          name: p.package?.name,
          version: p.package?.version,
          ecosystem: p.package?.ecosystem,
          vulnerabilities: (p.vulnerabilities || []).map(v => ({
            id: v.id,
            summary: v.summary,
            severity: v.database_specific?.severity || 'unknown'
          }))
        }))
      }))
    };
  } catch (err) {
    try {
      const report = JSON.parse(err.stdout || '{}');
      return { tool: 'osv-scanner', success: true, results: report.results || [] };
    } catch {
      return { tool: 'osv-scanner', success: false, error: err.message?.split('\n')[0] };
    }
  }
}

/**
 * Audit all dependencies in a project.
 *
 * @param {string} repoPath - Path to repository
 * @param {object} [options]
 * @param {boolean} [options.npmAudit=true] - Run npm audit
 * @param {boolean} [options.pipAudit=true] - Run pip-audit
 * @param {boolean} [options.osvScanner=true] - Run osv-scanner
 * @returns {object} Combined audit results
 */
export function auditDependencies(repoPath, options = {}) {
  const resolved = resolve(repoPath);
  const {
    npmAudit: runNpm = true,
    pipAudit: runPip = true,
    osvScanner: runOsv = true
  } = options;

  const ecosystems = detectEcosystems(resolved);
  const audits = [];

  if (runNpm && ecosystems.includes('npm')) {
    audits.push(runNpmAudit(resolved));
  }
  if (runPip && ecosystems.includes('pip')) {
    audits.push(runPipAudit(resolved));
  }
  if (runOsv) {
    audits.push(runOsvScanner(resolved));
  }

  // Count totals
  let totalVulnerabilities = 0;
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;

  for (const audit of audits) {
    if (!audit.success) continue;
    if (audit.advisories) {
      totalVulnerabilities += audit.advisories.length;
      for (const a of audit.advisories) {
        if (a.severity === 'critical') critical++;
        else if (a.severity === 'high') high++;
        else if (a.severity === 'moderate' || a.severity === 'medium') medium++;
        else low++;
      }
    }
    if (audit.vulnerabilities && Array.isArray(audit.vulnerabilities)) {
      totalVulnerabilities += audit.vulnerabilities.length;
    }
  }

  return {
    scanner: 'dependency-audit',
    repoPath: resolved,
    timestamp: new Date().toISOString(),
    ecosystems,
    totalVulnerabilities,
    bySeverity: { critical, high, medium, low },
    audits
  };
}
