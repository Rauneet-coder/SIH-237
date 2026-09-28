# Engineering Handoff & Audit Remediation Report

> Project: SIH26237 — Cryptographic Attribution & Immutable Decryption Provenance System  
> Branch: `fix/security-and-correctness-repairs`  
> Review Document Remediated: `docs/reviews/HLD-follow-up-d0cb080.md`  
> Date: 2026-09-28  

---

## 1. Executive Summary

This engineering handoff documents the systematic resolution of all 13 critical security, correctness, and architectural defects identified in `docs/reviews/HLD-follow-up-d0cb080.md`.

All fixes have been implemented on the active branch `fix/security-and-correctness-repairs`. The system preserves all user code, maintains the approved warm light visual theme, and strictly enforces fail-closed cryptographic gates across all services.

**Key Verification Milestones:**
- **Backend Test Suite:** 127/127 tests pass across 37 suites (`npm test`).
- **Key Agent Daemon Suite:** 12/12 dedicated negative security and custody tests pass.
- **Security Regression Suite:** 13/13 dedicated fail-closed and anti-fraud tests pass.
- **Frontend Production Build:** Next.js 14 App Router compiles with 0 TypeScript/linting errors (`npm run build`).

---

## 2. Audit Findings Resolved & Verification Evidence

### Finding 1: Key Agent Authentication & Replay Protection
- **Defect:** `HMAC_SECRET` was declared but unused; endpoints accepted arbitrary unauthenticated HTTP requests.
- **Resolution:** Implemented `keyAgentAuth.js` canonical request signing covering `method\npath\nrecipientId\ntimestamp\nnonce\nbodyHash`. Protected routes (`/provision`, `/rotate`, `/decapsulate`, `/sign`, `/revoke`, `/has`) enforce HMAC-SHA256 verification with a 60-second freshness window and a sliding nonce replay cache.
- **Evidence:** `tests/keyagent-daemon.test.js` tests 2–7 verify missing auth, tampered bodies, expired timestamps, replayed nonces, and recipient mismatches all reject with HTTP 401/403.

### Finding 2: Key Custody & Restart Persistence
- **Defect:** Keys were stored in an in-memory `Map()`, disappearing on process restart. In-process fallback bypassed security boundaries.
- **Resolution:** Implemented encrypted persistent file keystore (`storage/key-agent-keystore/keystore.enc` + `daemon.master.key`) encrypted with `AES-256-GCM` and strict POSIX `0600` file permissions. In secure mode (`KEY_AGENT_SECURE_MODE=true`), in-process fallback is completely disabled.
- **Evidence:** `tests/keyagent-daemon.test.js` test 11 verifies private keys persist across daemon re-initialization.

### Finding 3: Insecure Provisioning Overwrite
- **Defect:** Calling `/provision` on an existing recipient silently generated new keys, destroying earlier keys and breaking decryption of past documents.
- **Resolution:** `/provision` is now strictly idempotent. If active keys exist, it returns the existing public keys and sets `alreadyExisted: true` without altering stored private keys.
- **Evidence:** `tests/keyagent-daemon.test.js` test 9 verifies idempotence.

### Finding 4: Insecure Clearance Default
- **Defect:** New user registrations defaulted to `TOP_SECRET` clearance.
- **Resolution:** Changed `User` schema default clearance to least-privilege `RESTRICTED`. Public self-registration of privileged roles (`ADMIN`, `SENDER`) is rejected. Created audited role/clearance management endpoints (`PATCH /api/auth/users/:id/role`, `PATCH /api/auth/users/:id/clearance`) with `clearanceHistory` logging. First-user bootstrap allows initial setup when `userCount === 0`.
- **Evidence:** `tests/identity.test.js` verifies default permissions; `backend/src/scripts/audit-clearances.js` provides operator review.

### Finding 5: Device Proof & Runtime Bug
- **Defect:** Device challenge in `authController.js` called Node crypto methods without importing `node:crypto`. Missing `deviceId` bypassed `validateDeviceBinding`.
- **Resolution:** Added `const crypto = require('node:crypto')`. Updated `validateDeviceBinding` in `auth.js` to strictly require `x-device-id` and check device status against the database.
- **Evidence:** `tests/security-fixes.test.js` tests 1–3 verify missing and rogue devices are rejected with HTTP 403.

### Finding 6: Render Gate Device Mismatch
- **Defect:** Document render did not compare the requesting device with the device bound during session creation.
- **Resolution:** `decryptionSessionService.getSessionDocument` compares `reqDeviceId === session.deviceId`. Mismatched devices trigger `AUTHORIZATION_ERROR` / `FAIL_CLOSED_RELEASE_DENIED`.
- **Evidence:** `tests/security-fixes.test.js` test 3 verifies device mismatch rejection.

### Finding 7: Dynamic Key/Device Revocation Check
- **Defect:** Revoking a recipient's key or device after preparation did not block subsequent document release on render.
- **Resolution:** `getSessionDocument` re-evaluates `user.keyStatus === 'ACTIVE'`, `device.status === 'ACTIVE'`, and access temporal windows on every single render call.
- **Evidence:** `tests/security-fixes.test.js` test 5 verifies revocation after preparation blocks release.

### Finding 8: Session Close & Memory Zeroization
- **Defect:** No endpoint existed to close or revoke an active session. Viewer Lock button only cleared local state.
- **Resolution:** Implemented `POST /api/sessions/:sessionId/close` which transitions session status to `REVOKED` and purges the decrypted render buffer from server memory. Wired `api.closeSession` into `handleLockViewer` in `InboxConsole.tsx`.
- **Evidence:** `tests/security-fixes.test.js` test 4 verifies session close followed by render returns 403.

### Finding 9: Fail-Closed Watermarking
- **Defect:** Watermark service failure silently fell back to appending a text comment and still released the document. Hardcoded 0.95 confidence claims were made.
- **Resolution:** When `WATERMARK_REQUIRED=true`, any watermark service error throws `WatermarkError`, blocking document release. Removed hardcoded PSNR/SSIM/confidence metrics. Added `getCapabilities()` disclosure.
- **Evidence:** `tests/security-fixes.test.js` test 6 verifies fail-closed release denial.

### Finding 10: Forensic Evidence Binding & Marker Fraud
- **Defect:** Missing source document defaulted `documentHashValid = true`. Commitment checking inspected length only. Copying a valid watermark string into a foreign PDF produced false attribution.
- **Resolution:** Initialized `documentHashValid = false`. Recomputed commitments from authenticated session parameters. `fingerprintService.computeStructuralFingerprint` compares normalized structural layout and vocabulary tokens between suspect file and original document, flagging `FRAUD_DETECTED` on mismatch.
- **Evidence:** `tests/security-fixes.test.js` test 7 and 8 verify marker fraud detection and inconclusive orphan handling.

### Finding 11: Provenance Hash-Chain Integrity (v2 Payload)
- **Defect:** The `details` object was omitted from the signed provenance hash chain, allowing undetected tampering with audit metadata.
- **Resolution:** Defined canonical payload v2 including `detailsHash = SHA256(canonical(details))`. Maintained backward-compatible verification for historical v1 records. Added in-process mutex preventing sequence race conditions.
- **Evidence:** `tests/security-fixes.test.js` test 9 verifies details tampering breaks chain verification.

### Finding 12: File Vault Validation & Storage Optimization
- **Defect:** PDF validation was bypassed during upload. 50MB ciphertexts were duplicated as Base64 strings in MongoDB alongside disk storage.
- **Resolution:** `documentService` executes `fileVaultService.validatePdfBuffer()` before encryption. When stored to filesystem vault (`storage/encrypted/`, mode `0600`), the Base64 ciphertext blob is omitted from MongoDB. Rollback cleans up files if database persistence fails.
- **Evidence:** `tests/security-fixes.test.js` test 10 and 11 verify validation and mode 0600 permissions.

### Finding 13: Removal of Client Demo Private Keys
- **Defect:** 5 hardcoded RSA private keys were embedded in client bundle `frontend/lib/demoKeys.ts`.
- **Resolution:** Emptied `DEMO_PRIVATE_KEYS` in `demoKeys.ts`. Private keys are loaded strictly from session/local memory or user key agents.
- **Evidence:** `frontend/lib/demoKeys.ts` has 0 hardcoded keys; Next.js builds cleanly.

---

## 3. Findings Still Blocked / Incomplete (Honest Disclosure)

1. **Physical Optical Camera/Scan Testbed:**
   - Digital vector PDF watermark embedding and digital marker extraction are fully verified.
   - Optical extraction from physical camera photos or printed/scanned pages requires a calibrated laboratory testbed (physical camera rig, varied ambient illumination, perspective tilts).
   - System transparently returns `opticalCameraExtraction: 'UNSUPPORTED_REQUIRES_PHYSICAL_TESTBED'`.

2. **Live Multi-Node Hyperledger Fabric SmartBFT:**
   - Single-laptop operation runs on the cryptographically authenticated Standalone Local Ledger (append-only, hashed, ML-DSA-65 signed).
   - SmartBFT consensus requires a multi-node Fabric 3.x cluster deployment.

3. **OS-Level Secure Enclave / TPM Hardware Integration:**
   - The Key Agent currently stores private keys in an AES-256-GCM encrypted local file keystore with strict POSIX `0600` permissions.
   - Direct integration with macOS Secure Enclave (`Security.framework`) or Linux TPM 2.0 PKCS#11 requires platform-specific native binaries.

---

## 4. Startup & Operating Instructions

### Prerequisites
- Node.js 20+ (Node.js v26.5.0 verified)
- MongoDB running on `127.0.0.1:27017`

### 1. Start Key Agent Daemon (Port 8002)
```bash
cd backend
node src/services/key-agent-server.js
```
*Health check:* `curl http://127.0.0.1:8002/health` -> `{"status":"ok","mode":"PERSISTENT_ENCRYPTED_FILE"}`

### 2. Start Backend API Server (Port 8000)
```bash
cd backend
npm run dev
```
*Health check:* `curl http://127.0.0.1:8000/health` -> `{"status":"ok","runtime":"Node.js"}`

### 3. Start Frontend Web Application (Port 3000)
```bash
cd frontend
npm run dev
```
*Access:* Open `http://localhost:3000` in browser.

---

## 5. Account Migration & Review Procedure

For databases initialized under legacy versions where accounts received `TOP_SECRET` clearance by default:

```bash
cd backend
# Audit existing accounts (dry-run):
node src/scripts/audit-clearances.js --audit

# Review and migrate non-admin accounts to RESTRICTED:
node src/scripts/audit-clearances.js --migrate
```

---

## 6. Changed Files Inventory

### Backend Core & Services
- `backend/src/config/env.js`: Configured security flags (`WATERMARK_REQUIRED`, `KEY_AGENT_SECURE_MODE`).
- `backend/src/services/keyAgentAuth.js` *(NEW)*: Canonical request signing and HMAC-SHA256 verification.
- `backend/src/services/key-agent-server.js`: Persistent encrypted keystore, HMAC request authentication, replay protection, idempotent provisioning.
- `backend/src/services/keyAgentClient.js`: Client HMAC signing, synchronous `hasRecipient` compatibility.
- `backend/src/services/watermarkBridge.js`: Fail-closed gate enforcement, removed hardcoded metrics, capability reporting.
- `backend/src/services/forensicService.js`: Recomputed commitments, anti-fraud structural layout matching, clear verdict separation.
- `backend/src/services/provenanceService.js`: Canonical payload v2 with `detailsHash`, concurrency mutex.
- `backend/src/services/fileVaultService.js`: PDF magic byte validation, mode 0600 file vault storage.
- `backend/src/services/documentService.js`: PDF pre-upload validation, database blob deduplication, rollback on failure.
- `backend/src/services/decryptionSessionService.js`: Atomic concurrency locking, device matching, dynamic key/device status verification, session close.
- `backend/src/services/fingerprintService.js`: Structural layout content fingerprinting with vocabulary tokenization.

### Models, Middleware & Controllers
- `backend/src/models/User.js`: Default clearance `RESTRICTED`, role/clearance normalization, `clearanceHistory`.
- `backend/src/models/Document.js`: Optional `encryptedBlob` when `storagePath` exists.
- `backend/src/models/ProvenanceLog.js`: Schema versioning, `detailsHash`.
- `backend/src/middleware/auth.js`: Enforced device validation, dynamic revocation checks.
- `backend/src/controllers/authController.js`: First-admin bootstrap, audited role/clearance handlers, device challenge expiration.
- `backend/src/controllers/documentController.js`: Classification and access-window parameters wired.
- `backend/src/controllers/sessionController.js`: Session close handler, deviceId forwarding.
- `backend/src/controllers/forensicController.js`: Suspect file buffer extraction forwarding.
- `backend/src/routes/authRoutes.js`: Exposed audited role/clearance routes.
- `backend/src/routes/sessionRoutes.js`: Exposed `POST /api/sessions/:id/close`.
- `backend/src/scripts/audit-clearances.js` *(NEW)*: Clearance audit and migration utility.

### Frontend
- `frontend/lib/demoKeys.ts`: Emptied hardcoded demo private keys.
- `frontend/lib/device.ts`: Cryptographically secure random values via Web Crypto API.
- `frontend/lib/api.ts`: Added `closeSession`, `investigateLeak`, `verifyForensicEvidence`, updated `DocumentMeta`.
- `frontend/components/consoles/InboxConsole.tsx`: Server session closure on Lock button.
- `frontend/components/consoles/ForensicsConsole.tsx`: Evidence investigation tab with dual verification matrix.

### Tests & Documentation
- `backend/tests/keyagent-daemon.test.js`: 12 negative security and custody tests.
- `backend/tests/security-fixes.test.js` *(NEW)*: 13 regression tests for audit findings.
- `backend/tests/session.test.js`, `fabric.test.js`, `encryption.test.js`, `identity.test.js`, `foundation.test.js`, `integration.test.js`: Adjusted to verify new security policies.
- `docs/engineering/PROJECT_STATE.md`: Updated project checklist and status.
- `docs/engineering/DECISIONS.md`: Documented ADR-006 through ADR-011.
- `docs/engineering/ACCEPTANCE_TESTS.md` *(NEW)*: Comprehensive test matrix and reproduction guide.
- `docs/engineering/HANDOFF.md` *(NEW)*: Audit remediation and handoff report.
