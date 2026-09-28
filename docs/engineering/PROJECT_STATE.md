# Project State

> Last updated: 2026-09-28  
> Branch: `fix/security-and-correctness-repairs`  
> Base Commit: `d0cb080`  
> Review Document: `docs/reviews/HLD-follow-up-d0cb080.md`  
> Status: AUDIT FINDINGS RESOLVED & VERIFIED

---

## 1. Verified Implementation Baseline

| Subsystem | Implemented Status | Verification Evidence | Audit Remediation Summary |
|---|---|---|---|
| **Key Agent Daemon & Custody** | Production-Hardened | `backend/tests/keyagent-daemon.test.js` (12/12 passing) | HMAC-SHA256 request authentication (`keyAgentAuth.js`), 60s sliding timestamp window, nonce replay cache, encrypted persistent keystore (`keystore.enc` + `daemon.master.key`, mode `0600`), idempotent provisioning without key overwrite, session/document binding on sign & decapsulate, disabled in-process fallback in secure mode. |
| **Enrollment & ABAC Clearance** | Production-Hardened | `backend/tests/identity.test.js` (5/5 passing) | Least-privilege default clearance (`RESTRICTED`), uppercase canonical role normalization, audited role/clearance administration endpoints (`PATCH /api/auth/users/:id/role`, `PATCH /api/auth/users/:id/clearance`), first-admin bootstrap procedure (`userCount === 0`), prohibited device reactivation for REVOKED/SUSPENDED hardware. |
| **Device Proof & Session Release** | Production-Hardened | `backend/tests/session.test.js` (7/7 passing), `backend/tests/security-fixes.test.js` (13/13 passing) | Fixed missing `node:crypto` import, enforced strict device binding at middleware boundary (`x-device-id`), device ownership matching on render, dynamic revocation checks for keys and devices on every release, atomic preparation concurrency locking, server-side session close endpoint (`POST /api/sessions/:id/close`), UI lock action triggers server closure and frees ephemeral render buffers. |
| **Forensic Watermarking** | Production-Hardened (Fail-Closed) | `backend/tests/foundation.test.js` (7/7 passing), `backend/tests/security-fixes.test.js` | Fail-closed document release denial when `WATERMARK_REQUIRED=true` (throws `WatermarkError`), removed unmeasured PSNR/SSIM/0.95 confidence claims, honest capability reporting (`getCapabilities()`), validation of PDF magic header (`%PDF-`) on all returned streams. |
| **Forensic Evidence Verification** | Production-Hardened | `backend/tests/forensics-stages.test.js` (11/11 passing), `backend/tests/security-fixes.test.js` | Initialized `documentHashValid = false`, recomputes watermark commitments from authenticated session parameters, detects marker-copying fraud by matching normalized structural content fingerprints between suspect file and original document, missing required evidence yields `INCONCLUSIVE`, separated ledger signature verification from evidence binding. |
| **Provenance Hash-Chain Integrity** | Production-Hardened | `backend/tests/provenance.test.js` (6/6 passing), `backend/tests/security-fixes.test.js` | Versioned canonical payload v2 including `detailsHash = SHA256(canonicalStringify(details))`, backward-compatible verification for historical v1 records, in-process mutex protecting concurrent sequence assignment, durable authority keys. |
| **File Vault & Document Storage** | Production-Hardened | `backend/tests/encryption.test.js` (5/5 passing), `backend/tests/security-fixes.test.js` | Strict `%PDF-` magic header validation, 50MB bound, ciphertext persisted to isolated filesystem vault (`storage/encrypted/`) with mode `0600`, omitted duplicated Base64 blobs from MongoDB, rollback cleanup on persistence failures, support for classification and temporal access windows (`validFrom`, `validUntil`). |
| **Frontend Integration & Viewer** | Production-Hardened | `npm run build` (Next.js 14 App Router, 0 errors) | Removed hardcoded private keys from `demoKeys.ts`, integrated `api.closeSession()` into `handleLockViewer` in `InboxConsole.tsx`, expanded `ForensicsConsole.tsx` with dual-column verification matrix (Ledger Integrity vs Evidence Binding) and engineering limitations disclosures. |

---

## 2. Completed Implementation Checklist (Remediating HLD-follow-up-d0cb080)

1. [x] **Key-Agent Daemon Mutual Authentication & Replay Protection**:
   - Authenticate `/provision`, `/decapsulate`, `/sign`, `/revoke`, `/has` via HMAC-SHA256 (`backend/src/services/keyAgentAuth.js`).
   - 60-second timestamp freshness window and sliding nonce replay cache.
   - Session ID and document ID binding enforced on sensitive operations.
2. [x] **Persistent Key Custody & Enclave Idempotency**:
   - AES-256-GCM encrypted keystore file (`storage/key-agent-keystore/keystore.enc` + `daemon.master.key`) with POSIX `0600` permissions.
   - Idempotent `/provision` returns existing public keys without destroying or overwriting active private keys.
   - Disabled silent in-process fallback in secure mode (`KEY_AGENT_SECURE_MODE=true`).
3. [x] **Least-Privilege Clearance & Enrollment Policy**:
   - `User` schema defaults clearance to `RESTRICTED` (least privilege).
   - Audited admin endpoints for role and clearance modifications (`clearanceHistory` tracking).
   - First-user bootstrap provisioned when `userCount === 0`.
   - Prevented reactivation of revoked devices during re-registration.
   - Created migration/audit script `backend/src/scripts/audit-clearances.js`.
4. [x] **Device Possession Proof & Release Enforcement**:
   - Fixed missing `node:crypto` import in `authController.js`.
   - Enforced `validateDeviceBinding` middleware to reject missing, revoked, or unregistered devices.
   - Atomic concurrency locking on decryption preparation via `activePreparations` Map.
   - `getSessionDocument` enforces device matching, dynamic key status check, device status check, and session expiry check.
   - Server-side session closure (`POST /api/sessions/:sessionId/close`) evicts ephemeral memory.
5. [x] **Watermark Fail-Closed Gate**:
   - Outage of watermarking engine strictly blocks document release when `WATERMARK_REQUIRED=true`.
   - Stripped hardcoded PSNR/SSIM/0.95 confidence claims.
   - Transparent capability reporting via `watermarkBridge.getCapabilities()`.
6. [x] **Forensic Evidence Binding & Commitment Verification**:
   - Initialized `documentHashValid = false` (missing document produces `INCONCLUSIVE`).
   - Watermark commitment recomputed from authenticated session derivation parameters.
   - Structural content layout matching detects marker-copying fraud when watermark is copied into unrelated documents.
   - Distinguishes ledger cryptographic signature verification from evidence attribution.
7. [x] **Provenance Audit Integrity**:
   - Canonical payload v2 incorporates `detailsHash`.
   - Preserved backward compatibility for historical v1 records.
   - Prevented sequence forks and tampering.
8. [x] **File Vault Validation & Storage Optimization**:
   - Pre-upload PDF validation enforces `%PDF-` header and 50MB bound.
   - Filesystem vault stores ciphertext with mode `0600`; omitted duplicated Base64 blob from MongoDB.
   - Controller wires classification and access-window constraints.
9. [x] **Frontend Viewer Integration & Honest Reporting**:
   - Lock viewer invokes server session closure.
   - Removed hardcoded private keys from client code.
   - Forensics console exposes evidence investigation tab with dual verification matrix.
10. [x] **Comprehensive Regression Testing**:
    - 127/127 tests passing across 37 test suites in `backend/` (`npm test`).
    - Dedicated test suites for key agent daemon (`keyagent-daemon.test.js`) and security regression fixes (`security-fixes.test.js`).
    - Next.js 14 frontend builds cleanly with 0 TypeScript/linting errors.

---

## 3. Infrastructure Status & Honest Capability Disclosures

- **Key Agent Daemon:** Implemented with AES-256-GCM persistent file keystore (mode `0600`) and HMAC-SHA256 authenticated API on `127.0.0.1:8002`.
- **Standalone Immutable Ledger:** Implemented in `fabricService.js` (append-only MongoDB collection with sequential indexing, canonical hash digests, and ML-DSA-65 signatures).
- **Hyperledger Fabric Gateway:** Scaffold exists in `fabricGateway.js` and `blockchain/chaincode/`; live multi-node SmartBFT consensus requires dedicated Fabric 3.x cluster infrastructure.
- **Watermark Engine:** Python FastAPI microservice bridge operational; digital vector embedding supported. Physical optical photo/scan extraction remains marked as **experimental/unverified** pending calibrated physical hardware testbeds.
