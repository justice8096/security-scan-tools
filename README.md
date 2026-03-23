# security-scan-tools

Unified security scanning CLI for codebases — OWASP LLM Top 10, dependency CVEs (npm/pip/osv), SAST patterns (CWE/CERT), and secrets detection. Zero dependencies. JSON output compatible with the [LLM Compliance Evidence Collection](https://github.com/justice8096/ai-compliance-plugin) pipeline.

## Install

```bash
npm install -g security-scan-tools
```

## Usage

```bash
# Full scan
security-scan ./my-project

# JSON output
security-scan ./my-project --json

# With compliance-config.json fields
security-scan ./my-project --json --compliance

# Individual scanners
security-scan ./my-project --owasp-only
security-scan ./my-project --deps-only
security-scan ./my-project --sast-only
security-scan ./my-project --secrets-only
```

## Scanners

| Scanner | Covers | External Tools |
|---------|--------|---------------|
| OWASP LLM Top 10 | 10 AI/LLM vulnerability categories (2025 edition) | None |
| Dependency Audit | CVEs in npm, pip, go, cargo, composer, ruby | npm audit, pip-audit, osv-scanner |
| SAST Patterns | SQL injection, command injection, XSS, path traversal, weak crypto, hardcoded secrets, unsafe deserialization, auth issues, error exposure, sensitive logging | None |
| Secrets Detection | AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, GCP, npm, PyPI, private keys, JWTs, database URIs | None |

## Compliance Integration

With `--compliance`, output includes fields for compliance-config.json:

- **Template 15** (Security Assessment) — Testing date, tools used, severity counts, risk assessment
- **Template 23** (Supply Chain Risk) — Ecosystem coverage, vulnerability counts, secrets detected

## Programmatic API

```javascript
import { runFullScan, scanOwaspLlm, auditDependencies, scanSastPatterns, detectSecrets } from 'security-scan-tools';

// Full scan
const results = runFullScan('./my-project', { compliance: true });

// Individual scanners
const owasp = scanOwaspLlm('./my-project');
const deps = auditDependencies('./my-project');
const sast = scanSastPatterns('./my-project');
const secrets = detectSecrets('./my-project');
```

## License

MIT
