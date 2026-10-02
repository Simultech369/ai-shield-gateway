import crypto from "node:crypto";

export const SOLIDITY_SCAN_RECEIPT_SCHEMA = "dizzy.solidity_scan_receipt.v1";

function sha256Hex(text) {
  return crypto.createHash("sha256").update(String(text ?? ""), "utf8").digest("hex");
}

const INVARIANT_RULES = [
  {
    id: "TX_ORIGIN_USAGE",
    severity: "HIGH",
    title: "Vulnerable Authorization via tx.origin",
    pattern: /tx\.origin/g,
    description: "tx.origin was detected in authorization logic. Use msg.sender instead to prevent phishing attacks.",
    remediation: "Replace tx.origin with msg.sender.",
  },
  {
    id: "UNCHECKED_ERC20_RETURN",
    severity: "MEDIUM",
    title: "Unchecked ERC-20 Transfer Return Value",
    pattern: /(?<!SafeERC20\.)(?<!IERC20\.)(?<!\b(?:bool\s+[a-zA-Z0-9_]+\s*=\s*))(?:\.[a-zA-Z0-9_]+\s*\.\s*(?:transfer|transferFrom)\s*\([^;)]+\);)/g,
    description: "ERC-20 transfer/transferFrom call without checking return value or using SafeERC20.",
    remediation: "Use OpenZeppelin's SafeERC20 (safeTransfer/safeTransferFrom) to handle non-standard tokens.",
  },
  {
    id: "DELEGATECALL_IN_LOOP",
    severity: "CRITICAL",
    title: "Delegatecall Inside Loop",
    pattern: /(?:for|while)\s*\([^)]*\)\s*\{[^}]*\.delegatecall\s*\(/gs,
    description: "Executing delegatecall inside a loop can lead to catastrophic state corruption or reentrancy.",
    remediation: "Avoid delegatecall in loops or strictly validate storage slot modifications.",
  },
  {
    id: "UNPROTECTED_SELFDESTRUCT",
    severity: "CRITICAL",
    title: "Deprecated / Dangerous selfdestruct Usage",
    pattern: /\b(?:selfdestruct|suicide)\s*\(/g,
    description: "selfdestruct is deprecated (EIP-6049 / EIP-6780) and can permanently freeze contract funds if unprotected.",
    remediation: "Remove selfdestruct or restrict to multisig governance.",
  },
  {
    id: "FLOATING_PRAGMA",
    severity: "LOW",
    title: "Floating Compiler Pragma",
    pattern: /pragma\s+solidity\s+\^/g,
    description: "Contracts should be deployed with the exact same compiler version they were tested against.",
    remediation: "Lock pragma to an exact version (e.g. pragma solidity 0.8.24;).",
  },
  {
    id: "DIVISION_BEFORE_MULTIPLICATION",
    severity: "MEDIUM",
    title: "Potential Precision Loss (Division Before Multiplication)",
    pattern: /\/\s*[a-zA-Z0-9_().]+\s*\*\s*[a-zA-Z0-9_().]+/g,
    description: "Integer division before multiplication discards the remainder, compounding rounding errors.",
    remediation: "Perform all multiplications before divisions where possible.",
  },
  {
    id: "MISSING_ZERO_ADDRESS_CHECK",
    severity: "LOW",
    title: "Potential Missing Zero Address Validation",
    pattern: /function\s+(?:set[A-Z][a-zA-Z0-9_]*|init[A-Z][a-zA-Z0-9_]*)\s*\([^)]*address\s+([a-zA-Z0-9_]+)[^)]*\)[^{]*\{(?![^}]*require\s*\(\s*\1\s*!=\s*address\s*\(\s*0\s*\))/gs,
    description: "Address setter function does not appear to check for address(0), risking black-holing governance or fees.",
    remediation: "Add require(newAddress != address(0), 'Zero address prohibited');",
  },
  {
    id: "INLINE_ASSEMBLY_USAGE",
    severity: "LOW",
    title: "Inline Assembly (assembly { ... })",
    pattern: /\bassembly\s*\{/g,
    description: "Inline assembly bypasses Solidity memory safety and type checking.",
    remediation: "Verify assembly memory safety annotations and ensure proper memory pointer management.",
  },
];

export function scanSolidityCode(sourceCode, options = {}) {
  if (typeof sourceCode !== "string" || !sourceCode.trim()) {
    throw new Error("Missing or empty Solidity source code string.");
  }

  const lines = sourceCode.split("\n");
  const issues = [];
  const checksRun = INVARIANT_RULES.length;

  for (const rule of INVARIANT_RULES) {
    const matches = sourceCode.matchAll(rule.pattern);
    for (const match of matches) {
      const matchIndex = match.index || 0;
      const lineNumber = sourceCode.slice(0, matchIndex).split("\n").length;
      const snippet = lines[lineNumber - 1] ? lines[lineNumber - 1].trim() : "";

      issues.push({
        rule_id: rule.id,
        severity: rule.severity,
        title: rule.title,
        line: lineNumber,
        snippet,
        description: rule.description,
        remediation: rule.remediation,
      });
    }
  }

  // Calculate security score
  let score = 100;
  for (const issue of issues) {
    if (issue.severity === "CRITICAL") score -= 30;
    else if (issue.severity === "HIGH") score -= 15;
    else if (issue.severity === "MEDIUM") score -= 8;
    else if (issue.severity === "LOW") score -= 3;
  }
  score = Math.max(0, Math.min(100, score));

  // Determine overall posture
  let posture = "PASSED";
  if (score < 50 || issues.some(i => i.severity === "CRITICAL")) {
    posture = "FAIL_HIGH_RISK";
  } else if (score < 80 || issues.some(i => i.severity === "HIGH")) {
    posture = "NEEDS_REVIEW";
  }

  const contentSha256 = sha256Hex(sourceCode);
  const scanTimestamp = new Date().toISOString();

  const receipt = {
    schema_version: SOLIDITY_SCAN_RECEIPT_SCHEMA,
    timestamp: scanTimestamp,
    source_sha256: contentSha256,
    total_lines: lines.length,
    rules_evaluated: checksRun,
    issues_found: issues.length,
    security_score: score,
    posture,
  };

  receipt.evidence_sha256 = sha256Hex(JSON.stringify(receipt));

  return {
    success: true,
    posture,
    security_score: score,
    total_issues: issues.length,
    issues,
    receipt,
  };
}
