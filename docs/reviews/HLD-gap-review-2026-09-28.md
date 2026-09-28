# Repository review against the supplied HLD

Date: 28 September 2026. Scope: local repository source and the attached six-stage HLD image. No application implementation was changed for this review.

## Overall assessment

The repository is a useful prototype with working cryptographic primitives, document distribution, a local signed hash chain, and partial post-quantum session processing. It does not yet implement the complete device-bound, permissioned-blockchain, camera-aware, print-traceable system in the HLD. A simple UI is appropriate; the missing work is primarily backend enforcement and integration.

Two paths currently coexist:

- UI path: Inbox -> `POST /api/documents/:id/decrypt` -> optional ML-KEM recovery or RSA fallback -> local RSA-signed audit -> appended Tardos marker -> downloadable plaintext document.
- Session path: `/api/sessions` -> preparation -> ML-KEM recovery -> session watermark -> ML-DSA signature -> Fabric service (currently MongoDB fallback) -> PDF response. The frontend does not call this path.

### Evidence and validation limits

Read application routes, controllers, services, models, frontend API/auth/viewer, Python embedding/extraction, Go chaincode, Compose and Fabric config. Ran `NODE_ENV=test node --test tests/crypto.test.js tests/pqc.test.js tests/collusion.test.js`: 21 tests passed, zero failed. This review did not execute MongoDB integration tests, a live Fabric deployment, Python watermark benchmarks, camera tests, or physical print/scan tests. Implementation existence is not proof of security or robustness.

## HLD coverage

| HLD capability | Repository status | What to add or fix |
| --- | --- | --- |
| Document ID and original SHA-256 hash | Implemented in `documentService.js` | Use longer collision-resistant identifiers; validate file contents and bind policy version to package. |
| Base structural/content fingerprint | Missing as a distinct feature | Create normalized text/layout fingerprints plus page identifiers. Store separately from exact file hash; test matching on partial documents. |
| Recipient registry | Partial: accounts, public keys, device records | Add controlled enrollment, department, clearance, certificate lifecycle and approved device ownership. |
| AES-256-GCM, encrypt once | Implemented and unit-tested | Preserve authentication checks and make all error paths clear transient secrets. |
| Per-recipient ML-KEM-768 | Algorithm mismatch: actual implementation uses ML-KEM-1024 | Decide a versioned algorithm contract. If HLD is binding, use 768 for new keys/envelopes; migrate/version existing records, do not merely change labels. |
| ML-DSA event signing | Implemented in session path | Move recipient signing out of the server process and integrate it into the actual UI path. |
| Authentication / optional MFA | Password + JWT; MFA absent | Add local/offline-capable second factor and enrollment/recovery procedures if required by policy. |
| RBAC + ABAC | Role helper exists but is not mounted on routes; no policy engine | Enforce roles and object access server-side; add versioned classification, clearance, department, time, device and camera rules. |
| Device registration/binding | Records exist; enforcement permissive | Require enrolled active device and cryptographic possession proof; bind session, JWT/auth context and requests to that device. |
| Camera, liveness, periodic checks | Missing | Add consented camera challenge flow and evidence record, freshness expiry and revalidation. Treat browser metadata as signals, not trusted hardware attestation. |
| Decryption session ID/nonce/expiry | Partial implementation | Enforce ownership, device equality, expiry and revocation on every action, including already-released sessions. Add concurrency controls and cleanup. |
| Per-session watermark | Implemented in alternative session path | Integrate UI; persist complete provenance needed for reconstruction and verification. |
| Glyph/typographic and recipient structural variants | Missing | Implement format-aware rendering variants and corresponding extraction, evaluated against layout fidelity and false positives. |
| Multi-region ECC | Partial: Reed-Solomon data in two tiny PDF text insertions | Add actual spatial/raster encoding and registration/decoding for camera, crop, scan and compression cases. |
| Full signed event schema | Partial | Add camera proof reference/status, policy version/decision, content fingerprint, software version and later print IDs. Sign one consistent canonical event. |
| Hash chain | RSA-signed MongoDB chain implemented | Include security-relevant details in signed payload, serialize concurrent appends, maintain historical verification keys and anchor checkpoints externally. |
| Offline Fabric + SmartBFT | Scaffold only; configured Fabric 2.5 / single Raft orderer | Implement Gateway connection and startup/readiness; require confirmed commits. Deploy/test the intended BFT topology separately. |
| Controlled secure viewer | Missing as described: current UI decrypts/downloads document bytes | Use session APIs, short-lived page rendering, revocation/timeout, visible dynamic attribution and activity events. Strong OS-level restrictions require managed endpoints. |
| Authorized printing + print gateway + PI-ID | Missing | Add policy-authorized print jobs, per-print/per-page markers, controlled spooler integration and signed lifecycle events. |
| Leak extraction from digital PDF | Partial metadata/text or appended-marker extraction | Unify extractor, ledger lookup, full signature verification and report generation. |
| Leak extraction from photos/scans/photocopies | Missing | Add image preprocessing, page/region localization, robust signal decoder and measured evaluation dataset. |
| Complete forensic evidence report | Partial Tardos scoring report | Include document/session/device/print evidence, verification results, uncertainty and evidence lineage. |
| Behavioral monitoring / anomaly alerts | Logging only; no monitoring workflow found | Add signed usage events, practical rules, alert storage and investigator review. |
| Air-gapped deployment | Not enforced by current config | Bundle fonts/dependencies/images, remove public network dependencies, apply network isolation and test cold startup without Internet. |

## Highest-priority correctness and security fixes

### 1. Self-selected privileged roles and unguarded operations

`backend/src/controllers/authController.js` accepts `role` from public registration. `backend/src/routes/documentRoutes.js` mounts authentication alone for upload, trace and simulation. The `authorizeRoles` helper is not used by the route modules. Audit queries similarly lack appropriate role/object scoping. Anyone who can register can request an admin/investigator role; authenticated users can reach operations their role should not permit.

Fix: default public enrollment to an unprivileged/pending identity; allow role changes only through approved administrative operations. Normalize role names to a single enum. Mount explicit role checks and document/case access checks on routes and service entry points. Validate authorization through negative tests, not UI visibility.

### 2. Session ownership and device checks are incomplete

`decryptionSessionService.prepareSession()` loads by session ID but does not first compare the authenticated recipient to the stored session owner or the supplied device to the stored device. It returns `ALREADY_RELEASED` before checking ownership/expiry. A different authorized recipient of the same document can potentially prepare another user's session with their own keys. `getSessionStatus()` has no owner filter. Unknown and suspended devices are not rejected; controller defaults to `DEV-DEFAULT`. Render checks owner/expiry but not current device proof or key/device revocation.

Fix: scope all reads to owner, require an enrolled ACTIVE device with verified request proof, reject device mismatches, and run expiry/revocation checks before early returns. Prevent concurrent prepare calls with atomic state transitions and idempotency. Log failure events to the provenance system. Add cross-user prepare/status/render, unknown-device, suspended-device, replay, concurrent-prepare and post-revocation tests.

### 3. The key agent is inside the backend

`keyAgentClient.js` stores ML-KEM and ML-DSA private keys in an in-process Map. This is a simulation, not an isolated workstation agent or HSM. The server can access recipient keys and produce signatures. Keys disappear after restart while public keys remain in MongoDB. `KEY_AGENT_URL` is configured but unused.

Fix: implement a recipient-side agent with an authenticated, narrowly scoped operation interface; keep recipient private keys on the user's device. Bind decapsulation/signing challenges to the specific event, document and session. Design recovery, rotation and historical public-key retention. Do not solve restart loss by saving recipient private keys in the application database.

### 4. The legacy path bypasses the intended release gate

The frontend calls the old decrypt endpoint and sends an RSA private key to the server. It does not require the session watermark, recipient ML-DSA signature, device proof, or Fabric commit. RSA fallback also remains possible after PQC key revocation because this route does not enforce keyStatus before legacy recovery. Upload can silently continue when ML-KEM envelope creation fails.

Fix: make one authenticated session pipeline authoritative for all plaintext release; disable the legacy release endpoint in the HLD deployment. Fail upload if an intended recipient cannot receive the required envelope. Connect frontend create/prepare/status/render methods and remove private-key submission from normal viewing. Keep any migration path explicit and outside the protected workflow.

### 5. Fabric is not connected, and verification can report success for invalid data

`fabricService.initGateway()` contains a connection placeholder and is not invoked during server startup. No contract is assigned and the Gateway package is absent from backend dependencies. Records fall back to MongoDB even if a real ledger was expected. `verifyEventIntegrity()` checks for non-empty fields and returns `verified: true`; it does not recompute the digest or verify ML-DSA. Chaincode checks required fields and prevents replacing an event ID, but does not cryptographically verify the supplied application signature.

Fix: initialize a real authenticated Gateway, verify readiness/commit status and fail closed on unavailable consensus. Clearly label simulation mode. Verify canonical payload, digest, signature, signer public-key version and ledger receipt independently. Preserve one event ID: the signed event currently generates `EVT-...` while the ledger receives `evt_<sessionId>`. Store the complete canonical event; currently fields such as deviceId are absent from the Fabric record even though they were signed. Add tampered signature/digest/key/event tests and real network integration tests.

### 6. Audit details are not protected and append/restart behavior needs work

The local canonical chain payload excludes `details`, where session IDs, watermark commitments, Fabric references and fingerprint hashes live. Editing these details would not change the verified entry hash. Concurrent appends read the same last entry and can contend on sequence allocation. If authority keys are not configured, a fresh RSA key is generated at startup, making earlier signatures unverifiable under the new key. Database hooks cannot protect records from an administrator with direct storage access, nor prove that a valid tail was never removed.

Fix: version the signed payload to cover all evidence, serialize or transactionally coordinate appends, retain historical authority public keys, and use durable key provisioning. Anchor chain heads in the independent ledger. Keep the existing ledger as history; do not rewrite old signed records during migration.

### 7. Watermark fallback is not optical attribution

`watermarkBridge.js` silently appends a PDF comment if the Python service fails and later assigns it 0.95 confidence. The legacy Tardos path appends readable JSON, including recipient ID. Python embeds PDF metadata and 0.1-point nearly white text; extraction opens only PDF data and reads metadata/text. There is no photo/scan decoder. The embedder reports fixed PSNR/SSIM values, not measurements. The frontend claim that a smartphone photograph can be traced is unsupported by this implementation.

Fix: remove unsupported claims and fixed quality/confidence assertions. Fail protected release if required watermark embedding fails. Add measured optical encoding/extraction and a test corpus for crop, rotation, photocopy, JPEG and camera capture. ECC only helps after usable signal recovery; it does not create a robust optical signal. Mark results inconclusive when evidence is insufficient. Ensure extracted markers are cross-checked against signed history and the actual document, since a copied marker alone is not proof of source.

### 8. Demo credentials and long-lived browser storage

`frontend/lib/demoKeys.ts` is imported into client code. `authContext.tsx` uses fixed demo passwords and persists JWTs and RSA keys in localStorage. Logout does not remove all per-user stored keys. These are demo conveniences, not a recipient key custody boundary.

Fix: make a separate explicit demo build/profile; omit bundled demo keys and account creation from production. Use an appropriate secure session design and the local key agent; do not persist raw recipient keys in browser localStorage.

### 9. File validation and storage mismatch

Upload accepts the client MIME type or JSON content without checking actual file format. The 50 MB upload limit exceeds the practical single-record capacity of the current MongoDB document approach, especially because ciphertext is Base64. `ENCRYPTED_STORAGE_DIR` and the Compose vault volume are not used; bytes remain in `Document.encryptedBlob`.

Fix: validate supported formats by parsing, enforce size/page/resource limits, and store encrypted bytes in a dedicated local vault or suitable chunked storage. Keep references, hashes and envelopes in MongoDB. Add rejection tests for invalid, oversized and resource-intensive PDFs.

### 10. UI/API contracts need integration tests

The simulation endpoint returns `simulation` and `tracingResult`; the frontend expects `report` and `syntheticWatermark`. Rendering the simulated result can fail. The frontend event union/overview expects `ENCRYPT_UPLOAD`, while backend emits `DOCUMENT_UPLOAD` and `DECRYPT_ATTEMPT`. Upload/detail responses also use `id` while some types require `_id`. An empty chain response omits fields expected by the frontend. The recent-activity endpoint sorts ascending, so a limited request gets the oldest entries.

Fix: define consistent versioned DTOs, normalize IDs/actions, align simulation response shape, return a stable verification schema even for empty ledgers and explicitly request newest activity. Add API contract and browser tests for live workflows.

## Missing workflow design without making the UI complex

Keep six main sections. Reveal details only when needed:

1. **Send document:** file, recipients and policy preset; advanced classification/device/time rules in a disclosure section.
2. **Secure inbox:** document list; selecting Open runs device/camera/policy preflight, then opens the session viewer with expiry and watermark.
3. **Activity ledger:** session timeline and genuine verification status. Expand a record to inspect signatures, device/camera evidence and policy decision.
4. **Investigations:** upload leak -> extraction -> candidate evidence -> verification -> report. Separate experiments from real cases.
5. **Key vault / Devices:** public identity, enrollment, device status and rotation/revocation. Private keys remain in the recipient agent.
6. **Print action inside viewer:** shown only when policy permits; approval, print instance ID and tracked job history. No additional top-level menu needed.

Use explicit states: checking, approved, denied, expired, service unavailable, verification failed, and inconclusive. Never present a fallback as a successful stronger guarantee.

## Extra or redundant components

- **Tardos collusion experiments:** useful optional research/demo capability; not an explicit HLD requirement. Move simulation under a lab feature flag until the core single-recipient/session evidence workflow works.
- **RSA parallel distribution and server signatures:** legacy architecture, not the HLD's primary ML-KEM/recipient ML-DSA path. Keep only if there is a documented migration requirement; otherwise retire the downgrade path.
- **IPFS container:** no application integration found. It is not required by this HLD. Remove from the default deployment or explicitly configure a private isolated deployment if later justified. `IPFS_PROFILE=server` alone does not demonstrate isolation.
- **Two audit stores:** local RSA chain plus Fabric-like Mongo collection may be useful as cache/mirror, but are currently separate sources of truth. Make Fabric authoritative and specify reconciliation and failure behavior.
- **Duplicate device records:** embedded `User.devices` and separate `Device` collection can drift. Select a canonical source.
- **Unused key-agent/offline/vault configuration:** wire it into actual behavior or remove it until implemented.
- **Public Google Fonts:** unnecessary runtime Internet dependency for an air-gapped UI. Bundle fonts locally or use system fonts.
- **Compose scaffolding:** CouchDB and peers are appropriate for a functioning Fabric network, but add operational weight while Gateway is disconnected. Use explicit demo and full-network profiles.

## Proposed implementation order and acceptance checks

### P0 — repair trust boundaries first

- Fix privileged self-registration, route/object authorization and session ownership/device checks.
- Make legacy plaintext release unavailable in secure mode; remove fallback claims.
- Make verification recompute hashes/signatures and cover evidence fields.
- Align frontend/backend contracts and clearly distinguish sample data from live state.
- Acceptance: unauthorized role, document, session and device access all fail; revoked identities cannot obtain fresh plaintext; tampered evidence never verifies.

### P1 — one complete vertical slice

- Real recipient-side key agent and versioned PQC envelopes.
- UI -> enrolled device -> policy -> session -> watermark -> recipient signature -> actual ledger commit -> viewer.
- Persist complete canonical events and reconcile retry/partial-commit behavior.
- Acceptance: restart does not destroy access or verification; concurrent retries do not produce contradictory records; ledger/watermark outages prevent release.

### P2 — remaining HLD capabilities

- Local PKI, policy administration, MFA, camera/liveness evidence and revalidation.
- Print gateway, per-print/page identity and signed print lifecycle.
- Photo/scan decoding, base-content/glyph fingerprints, calibrated forensic reports and alerts.
- Acceptance: measured optical recovery and false-positive rates, traceable print jobs and verified offline deployment. Do not claim complete HLD coverage before these tests exist.

## Resolve conflicting specifications

The supplied AGENTS rules emphasize RSA wrapping, RSA authority signatures, all crypto in `cryptoService.js`, and recipient keys held only by users. The HLD requires ML-KEM-768 and ML-DSA; the fresh LLD says not to substitute RSA; the code uses ML-KEM-1024, separate PQC services and in-server recipient key storage. Pick and document the authoritative target, runtime, algorithm versions and custody model before implementation. Treat this as a design decision, not a cosmetic label change.

Given the approaching hackathon deadline, prioritize a demonstrably correct vertical slice and label remaining features planned or experimental. The full HLD should not be represented as complete today.
