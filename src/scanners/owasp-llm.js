/**
 * OWASP Top 10 for LLM Applications (2025) Scanner
 *
 * Checks codebases for patterns indicating vulnerability to each of the
 * OWASP LLM Top 10 categories. Uses static analysis + config file inspection.
 *
 * Reference: https://genai.owasp.org/llm-top-10/
 */

import { readFileSync, existsSync } from 'fs';
import { execFileSync } from 'child_process';
import { join, resolve } from 'path';
import { walkFiles } from '../utils/file-walker.js';

/**
 * OWASP LLM Top 10 (2025) check definitions.
 */
export const OWASP_LLM_CHECKS = [
  {
    id: 'LLM01',
    name: 'Prompt Injection',
    description: 'Direct and indirect prompt injection vulnerabilities',
    patterns: [
      /user[\s_]?input.*(?:prompt|system[\s_]?message)/gi,
      /(?:concat|join|template|format).*(?:prompt|instruction)/gi,
      /\$\{.*\}.*(?:system|prompt|instruction)/gi,
      /f["'].*\{.*\}.*(?:system|prompt)/gi,
      /\.replace\(.*(?:prompt|system)/gi,
    ],
    configChecks: ['input_validation', 'prompt_template_separation'],
    severity: 'critical',
    mitigation: 'Separate system prompts from user input. Use parameterized prompt templates. Implement input sanitization.'
  },
  {
    id: 'LLM02',
    name: 'Sensitive Information Disclosure',
    description: 'LLM revealing sensitive data in outputs',
    patterns: [
      /(?:api[\s_]?key|secret|password|token|credential).*(?:prompt|context|system)/gi,
      /(?:PII|ssn|social[\s_]?security|credit[\s_]?card).*(?:include|inject|add)/gi,
      /\.env.*(?:load|read|parse).*(?:prompt|llm|model)/gi,
    ],
    configChecks: ['output_filtering', 'pii_redaction'],
    severity: 'high',
    mitigation: 'Filter sensitive data from LLM context. Implement output sanitization. Use PII detection on responses.'
  },
  {
    id: 'LLM03',
    name: 'Supply Chain Vulnerabilities',
    description: 'Compromised training data, models, or plugins',
    patterns: [
      /(?:download|fetch|load).*(?:model|weights|checkpoint).*(?:http|url)/gi,
      /(?:huggingface|hf).*(?:from_pretrained|download)/gi,
      /pip\s+install.*(?:--index-url|--extra-index)/gi,
    ],
    configChecks: ['model_provenance', 'dependency_pinning', 'sbom'],
    severity: 'high',
    mitigation: 'Verify model checksums. Pin dependencies. Maintain SBOM. Use trusted model registries only.'
  },
  {
    id: 'LLM04',
    name: 'Data and Model Poisoning',
    description: 'Manipulation of training data or fine-tuning',
    patterns: [
      /(?:fine[\s_]?tun|train|retrain).*(?:user[\s_]?data|upload|external)/gi,
      /(?:rlhf|feedback|preference).*(?:collect|store|submit)/gi,
    ],
    configChecks: ['training_data_validation', 'data_provenance'],
    severity: 'high',
    mitigation: 'Validate training data sources. Implement data lineage tracking. Monitor for distribution shifts.'
  },
  {
    id: 'LLM05',
    name: 'Improper Output Handling',
    description: 'Insufficient validation of LLM outputs before downstream use',
    patterns: [
      /(?:eval|exec|Function)\s*\(.*(?:response|output|completion|result)/gi,
      /innerHTML\s*=.*(?:response|output|completion)/gi,
      /dangerouslySetInnerHTML.*(?:response|output)/gi,
      /\$\(.*(?:response|output|completion)/gi,
      /(?:exec|spawn|system)\(.*(?:response|output|completion)/gi,
    ],
    configChecks: ['output_validation', 'sandboxed_execution'],
    severity: 'critical',
    mitigation: 'Never execute LLM output directly. Validate and sanitize all outputs. Use allowlists for structured responses.'
  },
  {
    id: 'LLM06',
    name: 'Excessive Agency',
    description: 'LLM granted too many permissions or capabilities',
    patterns: [
      /(?:tool|function|action).*(?:delete|remove|drop|exec|admin|sudo)/gi,
      /(?:allow|permit|grant).*(?:all|any|\*).*(?:tool|action|function)/gi,
      /(?:auto[\s_]?approve|no[\s_]?confirm|skip[\s_]?auth)/gi,
    ],
    configChecks: ['least_privilege', 'human_approval_required', 'action_allowlist'],
    severity: 'high',
    mitigation: 'Apply least privilege. Require human approval for destructive actions. Use action allowlists.'
  },
  {
    id: 'LLM07',
    name: 'System Prompt Leakage',
    description: 'System prompts exposed to users or attackers',
    patterns: [
      /system[\s_]?prompt.*(?:log|print|console|return|response|send)/gi,
      /(?:debug|verbose).*(?:system[\s_]?prompt|instruction)/gi,
      /(?:error|exception).*(?:prompt|system[\s_]?message).*(?:stack|trace|detail)/gi,
    ],
    configChecks: ['prompt_confidentiality', 'error_handling'],
    severity: 'medium',
    mitigation: 'Never log or return system prompts. Implement proper error handling that strips internal context.'
  },
  {
    id: 'LLM08',
    name: 'Vector and Embedding Weaknesses',
    description: 'Vulnerabilities in RAG and vector store implementations',
    patterns: [
      /(?:embed|vector|rag).*(?:inject|poison|manipulate)/gi,
      /(?:chromadb|pinecone|weaviate|qdrant|pgvector).*(?:upsert|insert).*(?:user|external)/gi,
      /(?:similarity|search).*(?:threshold|limit).*(?:0\.|none|null)/gi,
    ],
    configChecks: ['embedding_validation', 'access_control_vectors'],
    severity: 'medium',
    mitigation: 'Validate data before embedding. Implement access controls on vector stores. Set similarity thresholds.'
  },
  {
    id: 'LLM09',
    name: 'Misinformation',
    description: 'LLM generating false or misleading information',
    patterns: [
      /(?:hallucin|confabulat|fabricat).*(?:check|detect|filter)/gi,
      /(?:ground|fact[\s_]?check|verify).*(?:source|citation|reference)/gi,
    ],
    configChecks: ['grounding', 'citation_required', 'confidence_threshold'],
    severity: 'medium',
    mitigation: 'Implement grounding with source citations. Set confidence thresholds. Add fact-checking layers.'
  },
  {
    id: 'LLM10',
    name: 'Unbounded Consumption',
    description: 'Denial of service through resource exhaustion',
    patterns: [
      /(?:max[\s_]?tokens|max[\s_]?length).*(?:unlimited|infinity|-1|999999)/gi,
      /(?:rate[\s_]?limit|throttl).*(?:disabled|false|none|0)/gi,
      /(?:timeout|max[\s_]?time).*(?:none|null|0|infinity)/gi,
      /(?:retry|loop).*(?:unlimited|infinity|while\s*\(true\))/gi,
    ],
    configChecks: ['rate_limiting', 'token_limits', 'timeout_config'],
    severity: 'medium',
    mitigation: 'Set token limits. Implement rate limiting. Configure timeouts. Cap retry attempts.'
  }
];

/**
 * Scan a codebase for OWASP LLM Top 10 vulnerabilities.
 *
 * @param {string} repoPath - Path to repository
 * @param {object} [options]
 * @param {string[]} [options.exclude] - Glob patterns to exclude
 * @param {string[]} [options.extensions] - File extensions to scan (default: js,ts,py,jsx,tsx)
 * @returns {object} Scan results with findings per OWASP category
 */
export function scanOwaspLlm(repoPath, options = {}) {
  const {
    exclude = ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv'],
    extensions = ['.js', '.ts', '.py', '.jsx', '.tsx', '.mjs', '.cjs']
  } = options;

  const resolved = resolve(repoPath);
  const files = walkFiles(resolved, { exclude, extensions });

  const findings = [];
  const summary = {};

  for (const check of OWASP_LLM_CHECKS) {
    summary[check.id] = { name: check.name, severity: check.severity, findings: 0, files: [] };
  }

  for (const filePath of files) {
    let content;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch { continue; }

    const lines = content.split('\n');

    for (const check of OWASP_LLM_CHECKS) {
      for (const pattern of check.patterns) {
        // Reset regex lastIndex for global patterns
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(content)) !== null) {
          // Find line number
          const beforeMatch = content.substring(0, match.index);
          const lineNum = beforeMatch.split('\n').length;
          const lineContent = lines[lineNum - 1]?.trim() || '';

          // Skip if it's in a comment
          const isComment = lineContent.startsWith('//') || lineContent.startsWith('#') || lineContent.startsWith('*');

          findings.push({
            checkId: check.id,
            checkName: check.name,
            severity: check.severity,
            file: filePath.replace(resolved, '.').replace(/\\/g, '/'),
            line: lineNum,
            matchedText: match[0].substring(0, 100),
            lineContent: lineContent.substring(0, 200),
            isComment,
            mitigation: check.mitigation
          });

          summary[check.id].findings++;
          if (!summary[check.id].files.includes(filePath)) {
            summary[check.id].files.push(filePath);
          }

          // Prevent infinite loop on zero-length matches
          if (match.index === pattern.lastIndex) pattern.lastIndex++;
        }
      }
    }
  }

  const criticalCount = findings.filter(f => f.severity === 'critical' && !f.isComment).length;
  const highCount = findings.filter(f => f.severity === 'high' && !f.isComment).length;

  return {
    scanner: 'owasp-llm-top10',
    version: '2025',
    repoPath: resolved,
    timestamp: new Date().toISOString(),
    totalFindings: findings.length,
    codeFindings: findings.filter(f => !f.isComment).length,
    commentFindings: findings.filter(f => f.isComment).length,
    bySeverity: {
      critical: criticalCount,
      high: highCount,
      medium: findings.filter(f => f.severity === 'medium' && !f.isComment).length
    },
    summary,
    findings
  };
}
