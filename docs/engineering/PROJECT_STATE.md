# Project State

> Last updated: 2026-09-28  
> Branch: `feature/hld-implementation`

---

## Current Verified Behavior

| Feature | Status | Evidence |
|---|---|---|
| AES-256-GCM encrypt/decrypt | ✅ Working | 8/8 crypto tests pass |
| ML-KEM-1024 keygen/encaps/decaps | ✅ Working | 3/3 PQC KEM tests pass |
| ML-DSA-65 sign/verify | ✅ Working | 4/4 PQC DSA tests pass |
| HKDF-SHA256 key derivation | ✅ Working | Tested via key envelope round-trip |
| Authenticated DEK wrapping | ✅ Working | Tested via key envelope with AAD binding |
| Collusion-resistant fingerprinting | ✅ Working | 5/5 Tardos tests pass |
| RSA-2048 keygen/wrap/sign | ✅ Working | Legacy; to be retired from primary path |
| Hash-chain provenance (MongoDB) | ✅ Working | Append-only with RSA server signatures |
| Canonical event serialization | ✅ Working | RFC 8785 deterministic JSON |
| Docker Compose orchestration | ✅ Configured | MongoDB, IPFS, Fabric scaffold, watermark service, backend, frontend |
| Frontend warm light theme | ✅ Working | 6-tab workspace with auth |

## Known Issues (Security Critical)

1. **Self-selected privileged roles:** Registration accepts any `role` from request body
2. **No route-level authorization:** `authorizeRoles()` exists but is NOT mounted on routes
3. **Session ownership not checked:** Cross-user session access possible
4. **Legacy decrypt bypasses session security:** `POST /:id/decrypt` returns plaintext without watermark/signature/ledger
5. **Key Agent is in-process:** Private keys stored in backend Map; not a security boundary
6. **Fabric verification fake:** `verifyEventIntegrity()` returns `verified: true` without cryptographic checks
7. **Provenance details outside signed payload:** Editing `details` field doesn't change entry hash
8. **Demo credentials bundled:** `demoKeys.ts` has hardcoded RSA private keys imported in production code

## Active Milestone

**Milestone 2: Security Critical Fixes (P0)**

## Infrastructure Blockers

| Blocker | Impact | Workaround |
|---|---|---|
| MongoDB not running | Cannot test integration endpoints | `docker compose up mongodb` |
| Fabric not connected | Cannot test ledger commits | Standalone immutable ledger mode |
| No Fabric crypto-config | Cannot start Fabric peers | Generate with `cryptogen` or Fabric CA |
| Printer/spooler not available | Cannot test print gateway | Print integration tests blocked |
| Camera hardware access | Cannot test liveness verification | Camera tests blocked |

## Next Steps

1. ✅ Repository audit and HLD coverage matrix complete
2. 🔄 Begin P0 security fixes:
   - Fix role registration
   - Mount authorization on routes
   - Fix session ownership
   - Disable legacy decrypt
   - Fix provenance verification
3. Then: P1 vertical slice (key agent → viewer → ledger)

## Relevant Commits

- `5e678c4` — HEAD: Redesign frontend with simplified warm light workspace
- `c20e01d` — Update clean stack
