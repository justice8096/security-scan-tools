import { describe, it, expect } from 'vitest';
import { formatForCompliance } from '../src/compliance-formatter.js';

describe('formatForCompliance', () => {
  const mockResults = {
    scanDate: '2026-03-23T10:00:00.000Z',
    repoPath: '/test/repo',
    aggregate: { critical: 2, high: 3, medium: 5, low: 1 },
    scanners: {
      owaspLlm: {
        version: '2025',
        codeFindings: 4,
        summary: {
          LLM01: { name: 'Prompt Injection', severity: 'critical', findings: 2 },
          LLM05: { name: 'Improper Output Handling', severity: 'critical', findings: 2 }
        }
      },
      sast: {
        rulesChecked: 10,
        codeFindings: 3,
        bySeverity: { critical: 1, high: 1, medium: 1 }
      },
      dependencies: {
        ecosystems: ['npm', 'pip'],
        totalVulnerabilities: 5
      },
      secrets: {
        totalFindings: 1
      }
    }
  };

  it('maps to template 15 fields', () => {
    const fields = formatForCompliance(mockResults);
    expect(fields.template15_SecurityAssessment['Security Testing Performed']).toBe('Yes');
    expect(fields.template15_SecurityAssessment['Critical Vulnerabilities']).toBe('2');
  });

  it('maps to template 23 fields', () => {
    const fields = formatForCompliance(mockResults);
    expect(fields.template23_SupplyChainRisk['Dependency Audit Performed']).toBe('Yes');
    expect(fields.template23_SupplyChainRisk['Package Ecosystems']).toBe('npm, pip');
  });

  it('sets high risk when critical findings exist', () => {
    const fields = formatForCompliance(mockResults);
    expect(fields.template15_SecurityAssessment['Overall Risk Assessment']).toBe('High');
  });

  it('sets low risk when no critical/high findings', () => {
    const clean = { ...mockResults, aggregate: { critical: 0, high: 0, medium: 1, low: 0 }, scanners: {} };
    const fields = formatForCompliance(clean);
    expect(fields.template15_SecurityAssessment['Overall Risk Assessment']).toBe('Low');
  });

  it('includes OWASP LLM details', () => {
    const fields = formatForCompliance(mockResults);
    expect(fields.securityAssessment.details.owaspLlmTop10.version).toBe('2025');
    expect(fields.securityAssessment.details.owaspLlmTop10.categories).toHaveLength(2);
  });

  it('sets passesThreshold correctly', () => {
    const fields = formatForCompliance(mockResults);
    expect(fields.securityAssessment.passesThreshold).toBe(false);

    const clean = { ...mockResults, aggregate: { critical: 0, high: 0, medium: 1, low: 0 }, scanners: {} };
    const cleanFields = formatForCompliance(clean);
    expect(cleanFields.securityAssessment.passesThreshold).toBe(true);
  });
});
