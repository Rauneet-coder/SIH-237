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
