import assert from "node:assert/strict";
import { scanSolidityCode, SOLIDITY_SCAN_RECEIPT_SCHEMA } from "../src/engine/solidity_scanner.mjs";

console.log("=== Testing Solidity Invariant Scanner Engine ===");

// 1. Scan vulnerable contract
const vulnerableCode = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBank {
    address public owner;
    
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function withdraw() external {
        require(tx.origin == owner, "Not owner");
        selfdestruct(payable(owner));
    }
}
`;

const res = scanSolidityCode(vulnerableCode);
assert.equal(res.success, true);
assert(res.total_issues >= 3, `Expected at least 3 issues, got ${res.total_issues}`);
assert(res.issues.some(i => i.rule_id === "TX_ORIGIN_USAGE"));
assert(res.issues.some(i => i.rule_id === "UNPROTECTED_SELFDESTRUCT"));
assert(res.issues.some(i => i.rule_id === "FLOATING_PRAGMA"));
assert.equal(res.posture, "FAIL_HIGH_RISK");
assert.equal(res.receipt.schema_version, SOLIDITY_SCAN_RECEIPT_SCHEMA);
assert(res.receipt.evidence_sha256.length === 64);
console.log("✔ Detected critical and high severity Solidity vulnerabilities correctly");

// 2. Scan clean contract
const secureCode = `
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract SecureVault {
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    function checkOwner() external view returns (bool) {
        return msg.sender == owner;
    }
}
`;

const secureRes = scanSolidityCode(secureCode);
assert.equal(secureRes.success, true);
assert.equal(secureRes.total_issues, 0);
assert.equal(secureRes.security_score, 100);
assert.equal(secureRes.posture, "PASSED");
console.log("✔ Clean contract awarded 100/100 score and PASSED posture");

console.log("ALL SOLIDITY SCANNER TESTS PASSED CLEANLY!");
