#!/usr/bin/env node
/**
 * security-scan CLI — Run security scans from the command line.
 */

import { runFullScan } from './runner.js';

const args = process.argv.slice(2);
let repoPath = '.';
let jsonOutput = false;
let compliance = false;
let scanners = { owasp: true, deps: true, sast: true, secrets: true };

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--json') jsonOutput = true;
  else if (arg === '--compliance') compliance = true;
  else if (arg === '--owasp-only') { scanners = { owasp: true, deps: false, sast: false, secrets: false }; }
  else if (arg === '--deps-only') { scanners = { owasp: false, deps: true, sast: false, secrets: false }; }
  else if (arg === '--sast-only') { scanners = { owasp: false, deps: false, sast: true, secrets: false }; }
  else if (arg === '--secrets-only') { scanners = { owasp: false, deps: false, sast: false, secrets: true }; }
  else if (arg === '--no-owasp') scanners.owasp = false;
  else if (arg === '--no-deps') scanners.deps = false;
  else if (arg === '--no-sast') scanners.sast = false;
  else if (arg === '--no-secrets') scanners.secrets = false;
  else if (arg === '--help' || arg === '-h') {
    console.log(`Usage: security-scan [repo-path] [options]

Options:
  --json              Output as JSON
  --compliance        Include compliance-config.json formatted fields
  --owasp-only        Run only OWASP LLM Top 10 check
  --deps-only         Run only dependency vulnerability audit
  --sast-only         Run only SAST pattern scan
  --secrets-only      Run only secrets detection
  --no-owasp          Skip OWASP LLM check
  --no-deps           Skip dependency audit
  --no-sast           Skip SAST patterns
  --no-secrets        Skip secrets detection
  --help, -h          Show this help`);
    process.exit(0);
  }
  else if (!arg.startsWith('-')) repoPath = arg;
}

const results = runFullScan(repoPath, { ...scanners, compliance });

if (jsonOutput) {
  console.log(JSON.stringify(results, null, 2));
} else {
  console.log('\n=== Security Scan Report ===');
  console.log(`Repository: ${results.repoPath}`);
  console.log(`Date: ${results.scanDate}`);
  console.log(`\nAggregate Findings:`);
  console.log(`  Critical: ${results.aggregate.critical}`);
  console.log(`  High:     ${results.aggregate.high}`);
  console.log(`  Medium:   ${results.aggregate.medium}`);
  console.log(`  Low:      ${results.aggregate.low}`);

  for (const [name, scanner] of Object.entries(results.scanners)) {
    console.log(`\n--- ${name} ---`);
    if (scanner.totalFindings !== undefined) {
      console.log(`  Findings: ${scanner.totalFindings}`);
    }
    if (scanner.codeFindings !== undefined) {
      console.log(`  Code findings: ${scanner.codeFindings} (${scanner.commentFindings || 0} in comments)`);
    }
    if (scanner.ecosystems) {
      console.log(`  Ecosystems: ${scanner.ecosystems.join(', ')}`);
    }
    if (scanner.totalVulnerabilities !== undefined) {
      console.log(`  Vulnerabilities: ${scanner.totalVulnerabilities}`);
    }
  }

  if (results.aggregate.critical > 0) {
    console.log('\n Warning CRITICAL vulnerabilities found — review required before deployment');
  } else if (results.aggregate.high > 0) {
    console.log('\n Warning HIGH severity findings — review recommended');
  } else {
    console.log('\n Check mark No critical or high severity findings');
  }
}
