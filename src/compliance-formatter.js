/**
 * Format scan results for compliance-config.json integration.
 * Maps findings to Templates 15 (Security Assessment) and 23 (Supply Chain Risk).
 */

/**
 * Format scan results into compliance-config.json fields.
 *
 * @param {object} scanResults - Full scan results from runner
 * @returns {object} Fields for compliance-config.json
 */
export function formatForCompliance(scanResults) {
  const fields = {
    securityAssessment: {
      scanDate: scanResults.scanDate,
      toolsUsed: Object.keys(scanResults.scanners),
      aggregateSeverity: scanResults.aggregate,
      passesThreshold: (scanResults.aggregate.critical === 0 && scanResults.aggregate.high === 0),
      details: {}
    },
    supplyChainRisk: {
      dependencyAuditPerformed: !!scanResults.scanners.dependencies,
      ecosystemsCovered: scanResults.scanners.dependencies?.ecosystems || [],
      knownVulnerabilities: scanResults.scanners.dependencies?.totalVulnerabilities || 0,
      secretsDetected: scanResults.scanners.secrets?.totalFindings || 0
    }
  };

  // OWASP LLM findings summary
  if (scanResults.scanners.owaspLlm) {
    const owasp = scanResults.scanners.owaspLlm;
    fields.securityAssessment.details.owaspLlmTop10 = {
      version: owasp.version,
      totalFindings: owasp.codeFindings,
      categories: Object.entries(owasp.summary)
        .filter(([_, v]) => v.findings > 0)
        .map(([id, v]) => ({ id, name: v.name, severity: v.severity, count: v.findings }))
    };
  }

  // SAST findings summary
  if (scanResults.scanners.sast) {
    const sast = scanResults.scanners.sast;
    fields.securityAssessment.details.sast = {
      rulesChecked: sast.rulesChecked,
      totalFindings: sast.codeFindings,
      bySeverity: sast.bySeverity
    };
  }

  // Map to specific template fields
  fields.template15_SecurityAssessment = {
    'Security Testing Performed': 'Yes',
    'Testing Date': scanResults.scanDate.split('T')[0],
    'Tools Used': Object.keys(scanResults.scanners).join(', '),
    'Critical Vulnerabilities': String(scanResults.aggregate.critical),
    'High Vulnerabilities': String(scanResults.aggregate.high),
    'Overall Risk Assessment': scanResults.aggregate.critical > 0 ? 'High' :
      scanResults.aggregate.high > 0 ? 'Medium' : 'Low'
  };

  fields.template23_SupplyChainRisk = {
    'Dependency Audit Performed': fields.supplyChainRisk.dependencyAuditPerformed ? 'Yes' : 'No',
    'Package Ecosystems': fields.supplyChainRisk.ecosystemsCovered.join(', '),
    'Known Vulnerabilities': String(fields.supplyChainRisk.knownVulnerabilities),
    'Secrets Detected': String(fields.supplyChainRisk.secretsDetected)
  };

  return fields;
}
