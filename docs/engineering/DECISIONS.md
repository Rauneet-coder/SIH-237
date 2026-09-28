# Architecture Decisions Log

> Last updated: 2026-09-28

---

## ADR-001: ML-KEM-1024 vs ML-KEM-768

**Date:** 2026-09-28  
**Status:** DECIDED  
**Decision:** Keep ML-KEM-1024 (FIPS 203)

**Context:** The HLD diagram labels recipient key encapsulation as "ML-KEM-768". The SRS (requirement.md) specifies Kyber-1024 (FR-02, CR-02). The current implementation uses `ml_kem1024` from `@noble/post-quantum`. ML-KEM-1024 offers NIST Security Level 5 vs Level 3 for 768.

**Resolution:** The SRS is the authoritative requirements document. ML-KEM-1024 is retained. The HLD label is treated as a typographic discrepancy. All envelopes carry `kemAlgorithm: 'ML-KEM-1024'` with `keyVersion: '1.0'` for forward compatibility.

**Consequence:** No migration required. Document labels are corrected in engineering docs.

---

## ADR-002: RSA Retirement from Primary Workflow

**Date:** 2026-09-28  
**Status:** IN PROGRESS  
**Decision:** Remove RSA-OAEP key wrapping from document upload/decrypt pipeline

**Context:** The HLD specifies ML-KEM for all key encapsulation and ML-DSA for all event signing. The current code maintains parallel RSA-2048 wrapping and accepts RSA private keys via the decrypt API. This creates a downgrade path bypassing PQC security.

**Resolution:**  
- Phase 1: Remove RSA key wrapping from `uploadAndEncryptDocument()`. Remove `privateKey` acceptance from decrypt controller. Remove RSA private key from registration response.
- Phase 2: RSA server authority key for provenance hash-chain remains temporarily (signing server-side events only, not recipient events). Will be migrated to ML-DSA authority key.
- Existing encrypted documents with RSA envelopes remain accessible via migration endpoint (admin-only, logged).

**Consequence:** Frontend must stop sending RSA private keys. Demo key storage in localStorage removed. Legacy documents need documented migration path.

---

## ADR-003: Key Agent Boundary Implementation

**Date:** 2026-09-28  
**Status:** PLANNED  
**Decision:** Implement key agent as a separate local process with authenticated HTTP API

**Context:** The HLD requires recipient private keys to never enter the backend process. Current implementation stores keys in an in-memory Map within the backend process (`keyAgentClient.js`). This is a simulation, not a security boundary.

**Resolution:**  
- Phase 1: Extract KeyAgentStore to a standalone Node.js process listening on `localhost:8002`. Authenticate requests with HMAC-bound challenge tokens containing sessionId, documentId, and nonce.
- Phase 2: OS keychain integration (macOS Keychain / Linux secret-service) for private key at-rest protection.
- Phase 3: HSM-compatible interface for production deployment.

**Consequence:** Backend code path changes from direct method call to HTTP request. Tests need key agent process startup. Docker Compose adds key-agent service. Installation instructions change.

---

## ADR-004: Standalone vs Fabric Ledger

**Date:** 2026-09-28  
**Status:** DECIDED  
**Decision:** Implement cryptographically verified standalone ledger; Fabric as optional deployment target

**Context:** The HLD requires Hyperledger Fabric with SmartBFT. SmartBFT requires Fabric 3.x or a BFT plugin not available in Fabric 2.5. Setting up a functioning Fabric network requires crypto-config generation, channel creation, chaincode deployment, and Gateway connection. This is infrastructure-heavy for a single-laptop development environment.

**Resolution:**  
- The standalone MongoDB-based ledger is made cryptographically rigorous: recompute hashes, verify ML-DSA signatures, enforce immutability.
- Clearly label as "standalone immutable ledger" mode, not "Fabric".
- When Fabric infrastructure is available: connect via Gateway, use endorsed transactions, and reconcile with local mirror.
- SmartBFT requires Fabric 3.x or external BFT orderer; document this as a deployment requirement.

**Consequence:** The system works locally without Fabric infrastructure. Real BFT fault tolerance requires multi-machine deployment and is marked as deployment acceptance test (blocked on infrastructure).

---

## ADR-005: Watermark Strategy

**Date:** 2026-09-28  
**Status:** IN PROGRESS  
**Decision:** Multi-layer watermarking with honest capability assessment

**Context:** Current watermark implementation appends PDF metadata and tiny near-white text. This is not camera-resilient. The HLD requires invisible watermarks surviving photo/scan/crop. The Python watermark service exists but only reads PDF metadata.

**Resolution:**  
- Phase 1: Structural PDF watermarking using glyph spacing variation and content stream modifications. Measurably invisible but detectable by the extractor.
- Phase 2: Image-domain watermarking using DCT/DWT embedding (evaluated with PSNR/SSIM metrics).
- All confidence scores and robustness claims must be measured, never hardcoded.
- If watermark embedding fails, document release is denied (fail-closed).
- Camera/scan resilience marked as experimental until measured evaluation dataset exists.

**Consequence:** Watermark extraction confidence will initially be lower for transformed documents. Claims are bounded by actual measurements.

---

## ADR-006: Key-Agent Daemon Authentication and Encrypted File Custody

**Date:** 2026-09-28  
**Status:** DECIDED  
**Decision:** AES-256-GCM encrypted keystore file with 0600 permissions and HMAC-SHA256 authenticated HTTP daemon

**Context:** The Key Agent daemon (`key-agent-server.js`) had declared `HMAC_SECRET` but all endpoints were unauthenticated. Private keys lived in volatile memory (`Map()`), wiping all keys on process restart while MongoDB retained public keys. Provisioning could silently overwrite existing keys, and client fell back to in-process memory.

**Resolution:**  
- Implement HMAC-SHA256 request authentication covering `timestamp`, `nonce`, `method`, `path`, `recipientId`, and payload `bodyHash`.
- Enforce 60-second timestamp freshness window and sliding replay nonce cache.
- Private keys persisted on the Key Agent host in `storage/key-agent-keystore/keystore.enc`, encrypted with AES-256-GCM using a daemon master key file with POSIX `0600` permissions.
- Disallow silent in-process fallback when `KEY_AGENT_SECURE_MODE=true` (fail-closed if daemon is unreachable).
- Make `/provision` idempotent: return existing public keys if already provisioned, block unauthorized overwrites. Add explicit `/rotate` and `/revoke` endpoints.

**Consequence:** Keystore survives restarts. Private keys never leave the daemon. Daemon rejects forged or replayed requests.

---

## ADR-007: Least-Privilege Enrollment and Clearance Governance

**Date:** 2026-09-28  
**Status:** DECIDED  
**Decision:** Default `RESTRICTED` clearance, explicit sender approval, first-admin bootstrap

**Context:** `User.js` had defaulted `clearance` to `TOP_SECRET` as a developer convenience. Self-registration allowed claiming `sender` or `admin` roles, and re-registration could reactivate revoked devices.

**Resolution:**  
- Default `clearance` changed to `RESTRICTED` (least privilege).
- Public registration allows only role `recipient`. Senders and admins must be promoted by an existing administrator.
- First administrator bootstrap: If `User.countDocuments() === 0`, initial user is created as `admin` with `TOP_SECRET` clearance.
- Add `PATCH /api/auth/users/:userId/clearance` and `PATCH /api/auth/users/:userId/role` with audit logging.
- Prohibit re-registration or activation of devices in `REVOKED` state.
- Provide `audit-clearances.js` review script for operators to audit historical accounts.

**Consequence:** Tests requiring elevated clearance must explicitly create accounts with required clearance or promote them.

---

## ADR-008: Cryptographic Device Proof & Continuous Release Enforcement

**Date:** 2026-09-28  
**Status:** DECIDED  
**Decision:** Bound challenge-response proof, strict device identity verification on prepare and render, server-side session closure

**Context:** `authController.js` failed device challenges due to missing `node:crypto` import. Fingerprint was used as HMAC secret. Missing device header was allowed. Render did not verify device identity or recheck key revocation. There was no server-side viewer lock/close endpoint.

**Resolution:**  
- Fix `node:crypto` import.
- Issue cryptographic challenges bound to `(userId, deviceId, purpose, sessionId, expiry)`.
- Enforce one-time consumption with 2-minute expiration.
- Reject missing or mismatched device headers at middleware and service layers.
- In `getSessionDocument()` (render), verify that the requesting device exactly matches the session's enrolled device, recheck key status (not `REVOKED`), and verify the document's access window.
- Add `POST /api/sessions/:sessionId/close` endpoint invoked when user locks viewer or navigates away.

**Consequence:** Device hijacking, session replay across devices, and rendering after key revocation are blocked.

---

## ADR-009: Fail-Closed Watermarking and Capability Disclosures

**Date:** 2026-09-28  
**Status:** DECIDED  
**Decision:** Fail-closed document release if watermark generation fails; honest capability disclosures

**Context:** `watermarkBridge.js` silently appended a plaintext comment `% SIH237_FORENSIC_TAG:...` if the Python watermarking service failed, releasing unwatermarked documents. Hardcoded PSNR (42.5 dB) and SSIM (0.985) metrics were returned.

**Resolution:**  
- When `WATERMARK_REQUIRED=true` (production default), watermark service failure immediately throws `WatermarkError` and aborts decryption/render (fail-closed).
- Remove hardcoded PSNR/SSIM/confidence metrics. Replace with measured values or explicit capability status (`DIGITAL_VECTOR_WATERMARKED`, `CAMERA_EXTRACTION_UNVERIFIED`).
- Explicitly label photo/scan extraction as requiring a physical-distortion testbed before claiming robustness.

**Consequence:** Outages in watermarking prevent unwatermarked document leaks.

---

## ADR-010: Forensic Evidence Attribution & Verification Lineage

**Date:** 2026-09-28  
**Status:** DECIDED  
**Decision:** Separate ledger integrity verification from evidence attribution; recompute commitments from authenticated session records

**Context:** Forensic verification checked `length === 64` for watermark commitments and left `documentHashValid=true` when documents were missing. Client-supplied document hashes were trusted. Copying a valid watermark string into an unrelated file could produce false attribution.

**Resolution:**  
- Distinguish `ledgerSignatureValid` (cryptographic proof that the record is unaltered on ledger) from `attributionVerified` (cryptographic and content binding to the suspect artifact).
- Recompute watermark commitment using the canonical session event and document ID.
- Compare normalized structural/content fingerprints between suspect evidence and original source document.
- If source document or evidence is missing, return `INCONCLUSIVE` or `INVALID`, never `true`.
- Disclose verification limitations and methodology in all audit reports.

**Consequence:** Forged or copied forensic markers no longer trigger false attribution.

---

## ADR-011: Audit Trail Integrity and Canonical Payload Versioning

**Date:** 2026-09-28  
**Status:** DECIDED  
**Decision:** Canonical Payload v2 including `detailsHash`, preserving backward compatibility for v1

**Context:** `provenanceService.js` signed sequence, prevHash, docId, recipientId, action, status, timestamp, but excluded the `details` object (session ID, watermark commitment, device ID, fabricTxId). Tampering with details was undetected by the signature.

**Resolution:**  
- Define canonical payload v2: `entryHash = SHA256(seq:prevHash:docId:recipientId:action:status:timestamp:detailsHash:v2)`.
- `detailsHash = SHA256(canonicalStringify(details))`.
- Backward compatibility: verify historical entries with v1 format if `schemaVersion` is absent or 1.
- In-memory lock / atomic sequence counter to prevent race conditions in concurrent provenance append.

**Consequence:** Every audit field is cryptographically signed; historical logs remain verifiable.
