# security-scan-tools

## Purpose
Unified security scanning CLI that runs OWASP LLM Top 10 checks, dependency CVE auditing, SAST pattern detection, and secrets scanning against any codebase. Outputs JSON compatible with the compliance-config.json pipeline for automated evidence collection.

## Tools & Stack
- **Runtime**: Node.js 18+ (ESM modules)
- **Test framework**: vitest
- **External tools** (optional, for dependency scanning): npm audit, pip-audit, osv-scanner
- **Zero npm dependencies** — all scanners use Node.js built-ins only

## Directory Structure
```
src/
  index.js              — Public API exports
  cli.js                — CLI entry point (security-scan command)
  runner.js             — Full scan orchestrator
  compliance-formatter.js — Maps results to compliance Templates 15 + 23
  scanners/
    owasp-llm.js        — OWASP Top 10 for LLM Applications (2025)
    dependency-audit.js  — npm audit / pip-audit / osv-scanner wrapper
    sast-patterns.js     — CWE/CERT static analysis patterns
    secrets-detector.js  — API key and credential detection
  utils/
    file-walker.js       — Recursive directory traversal
tests/                   — vitest test suites
skills/                  — Claude Code skills
```

## Key Commands
- `npm test` — Run vitest tests
- `node src/cli.js <repo-path>` — Run all scanners
- `node src/cli.js <repo-path> --json` — JSON output
- `node src/cli.js <repo-path> --json --compliance` — JSON with compliance fields
- `node src/cli.js <repo-path> --owasp-only` — OWASP LLM Top 10 only
- `node src/cli.js <repo-path> --sast-only` — SAST patterns only
- `node src/cli.js <repo-path> --secrets-only` — Secrets detection only
- `node src/cli.js <repo-path> --deps-only` — Dependency audit only

## Technical Notes
- All scanners use regex pattern matching on source code — no AST parsing required
- Findings in comments are flagged with `isComment: true` for filtering
- Secrets are masked in output (first 8 + last 4 chars shown)
- Dependency scanner gracefully falls back when external tools aren't installed
- OWASP LLM checks based on the 2025 revision of the OWASP Top 10 for LLM Applications
- SAST rules reference both CWE IDs and CERT secure coding standards
- Compliance formatter maps to Templates 15 (Security Assessment) and 23 (Supply Chain Risk)

## Compliance Integration
Output with `--compliance` flag produces fields that can be merged into compliance-config.json:
```json
{
  "securityAssessment": { ... },
  "supplyChainRisk": { ... },
  "template15_SecurityAssessment": { ... },
  "template23_SupplyChainRisk": { ... }
}
```
Run the full compliance pipeline:
1. `security-scan <repo> --json --compliance > scan-results.json`
2. Merge scan-results.json into compliance-config.json
3. Run `node autofill.js` from compliance-autofill

## LLM Compliance Integration
This project IS the security scanning component of the compliance evidence pipeline. It directly produces evidence for:
- **Security Assessment** (Template 15) — Automated security testing results
- **Supply Chain Risk** (Template 23) — Dependency vulnerability counts, ecosystem coverage
- **OWASP LLM Top 10** — AI-specific vulnerability detection
