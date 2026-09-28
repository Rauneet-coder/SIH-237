# Acceptance Tests & Security Verification Log

> Environment: Node.js v26.5.0, MongoDB v7.0+, macOS Darwin 24.6.0  
> Branch: `fix/security-and-correctness-repairs`  
> Test Runner: Built-in `node:test` + `node:assert/strict`  
> Frontend Verification: Next.js 14.2.35 Production Build  

---

## 1. Test Execution Summary

| Test Suite File | Domain / Focus Area | Tests Executed | Passed | Failed |
|---|---|---|---|---|
| `tests/keyagent-daemon.test.js` | HMAC Auth, Replay Cache, POSIX 0600 Keystore, Restart Persistence | 12 | 12 | 0 |
| `tests/security-fixes.test.js` | Device Proof, Render Gate, Fail-Closed Watermark, Anti-Fraud, FileVault | 13 | 13 | 0 |
| `tests/forensics-stages.test.js` | Forensic Lineage, Tamper Alerts, ML-DSA Ledger Verification | 11 | 11 | 0 |
| `tests/integration.test.js` | End-to-End REST Flows, Clearance Policies, Upload & Decrypt | 11 | 11 | 0 |
| `tests/fabric.test.js` | Standalone Ledger Invariants, Immutability, Event Querying | 8 | 8 | 0 |
| `tests/session.test.js` | 5-Stage Decryption Pipeline, RFC 8785 Canonical Serializer | 7 | 7 | 0 |
| `tests/foundation.test.js` | Error Hierarchy, Log Sanitization, Watermark Bridge | 7 | 7 | 0 |
| `tests/pqc.test.js` | NIST FIPS 203 (ML-KEM-1024) & FIPS 204 (ML-DSA-65) Algorithms | 7 | 7 | 0 |
| `tests/encryption.test.js` | Encrypt-Once AES-256-GCM + Per-Recipient Envelopes | 5 | 5 | 0 |
| `tests/identity.test.js` | Identity, Least-Privilege Defaults, Key Agent Enclave Boundary | 5 | 5 | 0 |
| `tests/provenance.test.js` | Genesis Block, Sequential Hash-Chain, Link Integrity | 6 | 6 | 0 |
| `tests/collusion.test.js` | Boneh-Shaw / Tardos Accusation Scores, Coalition Unmasking | 8 | 8 | 0 |
| `tests/crypto.test.js` | Native AES-256-GCM, RSA-OAEP, SHA-256 Hashing | 8 | 8 | 0 |
| `tests/security.test.js` | P0 Security Unit Regressions, Role Boundary, Signature Checks | 19 | 19 | 0 |
| **TOTALS** | **37 Test Suites Across Backend Subsystems** | **127** | **127** | **0** |

---

## 2. Negative Security Test Coverage

The following negative security scenarios were implemented and verified through automated tests:

| Negative Scenario | Expected Defense Response | Test File | Verified Status |
|---|---|---|---|
| Missing HMAC headers to Key Agent daemon | HTTP 401 Unauthorized | `keyagent-daemon.test.js` | PASS |
| Tampered request body to Key Agent daemon | HTTP 401 (HMAC mismatch) | `keyagent-daemon.test.js` | PASS |
| Expired timestamp (>60s) to Key Agent daemon | HTTP 401 (Expired request) | `keyagent-daemon.test.js` | PASS |
| Replayed request nonce to Key Agent daemon | HTTP 401 (Replay detected) | `keyagent-daemon.test.js` | PASS |
| Recipient ID mismatch in Key Agent request | HTTP 403 Forbidden | `keyagent-daemon.test.js` | PASS |
| Duplicate provisioning attempt | Idempotent (returns public keys, retains active private keys) | `keyagent-daemon.test.js` | PASS |
| Decapsulate/Sign after key revocation | HTTP 403 (Credentials revoked) | `keyagent-daemon.test.js` | PASS |
| Daemon restart key recovery | Private keys reloaded from encrypted file | `keyagent-daemon.test.js` | PASS |
| Missing `x-device-id` header on session creation | HTTP 403 `AUTHORIZATION_ERROR` | `security-fixes.test.js` | PASS |
| Unregistered / rogue device ID | HTTP 403 `AUTHORIZATION_ERROR` | `security-fixes.test.js` | PASS |
| Device mismatch on document render | HTTP 403 `AUTHORIZATION_ERROR` | `security-fixes.test.js` | PASS |
| Session close followed by render attempt | HTTP 403 `FAIL_CLOSED_RELEASE_DENIED` | `security-fixes.test.js` | PASS |
| Key revocation after session preparation | HTTP 403 `AUTHORIZATION_ERROR` | `security-fixes.test.js` | PASS |
| Concurrent session preparation requests | Atomic lock: exactly one execution succeeds | `security-fixes.test.js` | PASS |
| Watermark service outage when required | HTTP 403 `FAIL_CLOSED_RELEASE_DENIED` | `security-fixes.test.js` | PASS |
| Marker fraud: copying valid marker to foreign file | `evidenceBindingValid: false`, `FRAUD_DETECTED` | `security-fixes.test.js` | PASS |
| Forensic query with missing source document | `status: 'INCONCLUSIVE'`, `documentHashValid: false` | `security-fixes.test.js` | PASS |
| Tampering with `details` in ProvenanceLog | `verifyChain()` detects tampering at sequence number | `security-fixes.test.js` | PASS |
| Uploading non-PDF file | HTTP 400 `VALIDATION_ERROR` | `security-fixes.test.js` | PASS |
| Lower clearance user accessing higher classified doc | HTTP 403 Access Denied | `integration.test.js` | PASS |

---

## 3. How to Reproduce All Verifications Locally

### A. Run Full Backend Test Suite
```bash
cd backend
npm test
```
*Expected Result:* All 127 tests pass across 37 suites in ~25-30 seconds with 0 failures.

### B. Run Key Agent Daemon Security Tests Specifically
```bash
cd backend
node --test tests/keyagent-daemon.test.js
```
*Expected Result:* All 12 negative security, replay, and restart persistence tests pass.

### C. Run Audit Regression Fixes Suite Specifically
```bash
cd backend
node --test tests/security-fixes.test.js
```
*Expected Result:* All 13 fail-closed, device binding, and anti-fraud tests pass.

### D. Verify Frontend TypeScript Compilation and Production Bundle
```bash
cd frontend
npm run build
```
*Expected Result:* Next.js 14 compiles with 0 TypeScript and 0 linting errors, generating all static and dynamic pages.

---

## 4. Remaining Limitations (Honest Disclosure)

1. **Physical Optical Camera/Scan Distortion:**
   - The watermark engine decodes digital PDF streams and markers.
   - Resilience against physical print-and-scan or mobile camera capture under heavy geometric tilt, lighting glare, and resampling requires a calibrated physical hardware camera testbed.
   - Status: Marked as **UNSUPPORTED_REQUIRES_PHYSICAL_TESTBED** in capability reporting.

2. **Multi-Node Hyperledger Fabric SmartBFT:**
   - Single-laptop operation runs on the cryptographically authenticated Standalone Local Ledger.
   - Multi-node Byzantine Fault Tolerance requires a multi-machine Fabric 3.x cluster deployment.
