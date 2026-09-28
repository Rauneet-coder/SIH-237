# HLD follow-up review — d0cb080

Date: 2026-09-28. Reviewed local HEAD d0cb080 and changes since 5e678c4. Application code was not modified.

## Verdict

Improved, but not complete against the HLD and not ready for sensitive deployment. The commit description claiming complete Stage 1–6 coverage is not supported by the implementation.

## Verification performed

- Full backend `npm test`: 107 tests passed, zero failed. Uses dedicated local test databases; the command enables LEGACY_DECRYPT_ENABLED=true.
- Frontend `npm run build`: passed compilation/type checks and static build; external Google Fonts download warning remains.
- Focused direct invocation of the real device-challenge controller with a stubbed device lookup: failed with `crypto.randomBytes is not a function`. The controller does not import node:crypto. On runtimes without a global crypto object, the error would instead be an undefined identifier.
- Structural fingerprint probe: two buffers with identical PDF structural tokens and different text content produced the same fingerprint. This demonstrates that the function is not a distinguishing content fingerprint; it is not evidence of a SHA-256 collision.
- No live Fabric consensus, physical printer, camera/liveness or optical recovery acceptance tests were performed.

## Changes that are genuine improvements

- Public registration no longer assigns admin/investigator on request.
- Role middleware is now mounted on sensitive routes.
- Session prepare checks owner/device equality; status checks owner/admin.
- Legacy decrypt disabled by default.
- Inbox now creates/prepares/renders sessions.
- Local event verification recomputes digest and verifies ML-DSA.
- Filesystem ciphertext storage and forensic endpoints added.

## Outstanding findings, ordered by priority

1. **P1 — Unauthenticated key-agent daemon.** `backend/src/services/key-agent-server.js:214` dispatches provisioning, signing, decapsulation and revocation without authentication. HMAC_SECRET is declared but unused. A process able to reach this loopback service can request operations for arbitrary recipient IDs. Provisioning replaces existing keys. Authenticate and authorize every operation, bind it to a fresh operation-specific challenge, reject replay and uncontrolled reprovisioning.

2. **P1 — Highest clearance assigned by default.** `backend/src/models/User.js:40` defaults new accounts to TOP_SECRET. This defeats the intended clearance restriction for recipients granted document membership. Default to least privilege and require authorized, audited clearance assignment. Public sender enrollment also needs an explicit enrollment policy.

3. **P1 — Render does not enforce the session-bound device or key revocation.** `middleware/auth.js:90` passes through when device ID is omitted; with a supplied ID it checks enrollment but not equality with the session device. `decryptionSessionService.js:361` checks owner, state and expiry only. A valid owner token can fetch an existing released session without the original device proof, including after key revocation. Require the exact bound device, fresh cryptographic proof, current key/device state and current policy before every release. Device registration can also reactivate an existing revoked device (`authController.js:240`); restrict that operation.

4. **P1 — Watermark failure still releases content.** `watermarkBridge.js:109` appends a text marker when the Python service is unavailable. The full test run logged service unavailability followed by RELEASED. Disable this fallback in secure mode and test outage denial. The Python embedder/extractor still use metadata/tiny PDF text, fixed quality/confidence values and PDF-only extraction. Photos/scans, glyph analysis and robust optical decoding remain unimplemented.

5. **P1 — Fabric remains disconnected.** `fabricService.js:40` still contains the Gateway setup placeholder; startup does not initialize it. MongoDB fallback remains authoritative in practice. SmartBFT is not deployed. Configuration scaffolding is not a completed ledger integration. Require real validated commits in secure mode and label non-Fabric operation accurately.

6. **P1 — Forensic success does not prove evidence binding.** `forensicController.investigateLeak()` extracts an ID and forwards an optional client-supplied document hash; it does not establish that the submitted content matches the original. `forensicService.js:199` starts documentHashValid=true and leaves it true when the source record is missing. Commitment validation at line 225 checks only string length, not a derived commitment. A copied valid marker can therefore be mistaken for evidence of attribution. Verify actual content/structural evidence, recompute commitment using retained session context, and return inconclusive for missing evidence. A successful signature check authenticates a record, not the origin of arbitrary uploaded bytes.

7. **P1 — Key persistence and custody are unresolved.** Both daemon and fallback keys are volatile Maps. Backend provisioning falls back in-process outside tests. Backend routing knowledge is also volatile. Restart can destroy recipient decrypt/sign capability even while public keys and envelopes persist. Implement protected persistent recipient-side custody and remove secure-mode in-process fallback; test restart/rotation/revocation.

8. **P2 — Device challenge is broken and not an enforced possession boundary.** The missing node:crypto import causes a runtime failure. HMAC uses a client-generated/stored fingerprint instead of a protected device secret. No verified challenge result is required by session creation/preparation/render. Implement a device-held key and freshness-bound proof consumed by the protected operation, not just a standalone verification endpoint.

9. **P2 — Audit metadata still outside signed hash-chain payload.** `provenanceService.js:11` has not changed: details are not included. Watermark/session/Fabric references can change without invalidating the local signature. Version the payload and sign all relevant evidence; preserve historical entries. Authority key history and concurrent append handling also need work.

10. **P2 — File vault does not replace oversized database storage.** Upload stores both storagePath and encryptedBlob. Large files can still exceed MongoDB document capacity. The PDF validator exists but has no call sites in the upload pipeline. Wire actual parsing and resource limits into upload; persist ciphertext references instead of duplicating full Base64 data.

11. **P2 — Policy/camera fields are not complete features.** Upload controller does not pass classification or validity-window inputs into the service. Camera evidence/liveness are merely client-supplied strings stored on the session, not verified challenges. No periodic verification, full versioned ABAC decisions or MFA were found. Policies are checked at session creation rather than consistently rechecked before release.

12. **P2 — Viewer is not a controlled rendering boundary.** It downloads a full plaintext PDF Blob and uses an iframe with toolbar-hidden URL parameters. UI keyboard/copy restrictions and a client timer do not prevent extracting delivered bytes. Locking the view does not close/revoke the backend session. Implement a server/session lifecycle and a policy-appropriate rendering approach; document browser limits.

13. **P2 — HLD completion/documentation overclaims.** No print gateway, print-instance IDs, physical attribution, full PKI lifecycle or measured optical recovery implementation was found. New forensic endpoints are not integrated into the existing ForensicsConsole API path. PROJECT_STATE.md still lists old HEAD and old issues. Decisions downgrade Fabric and characterize ML-KEM-768 as a typo without evidence of user approval. Record scope decisions explicitly rather than marking omitted HLD features complete.

## Test coverage limitations

Several security tests duplicate simple role/ownership logic instead of invoking production handlers. Key-agent tests construct a separate test HTTP dispatcher rather than exercising the actual authenticated production handler (which is absent). The complete suite enables legacy decrypt and permits watermark fallback, so passing tests do not establish the intended production guarantees.

Add direct endpoint tests for unauthenticated key-agent requests, fresh-account clearance, missing/wrong device render, revocation after release, real device challenge, watermark outage, copied marker on unrelated content, source record absence, restart durability and production configuration with legacy release disabled.

## Recommended next milestone

Fix key-agent authorization/custody, least-privilege clearance and session release enforcement first. Then remove silent fallbacks, validate forensic evidence binding, repair actual device proof and connect Fabric. Only after those boundaries hold should remaining HLD features be called complete. Keep UI polish; do not use it as readiness evidence.
