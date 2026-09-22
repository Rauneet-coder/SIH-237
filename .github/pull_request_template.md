## 📌 Description
<!-- Provide a brief description of the changes introduced by this pull request. -->

## 🔗 Related Issue / Milestone
- Milestone: <!-- e.g., M0 Infrastructure / M1 Auth & KMS -->
- Issue: <!-- #123 -->

## 🛠️ Type of Change
- [ ] `feat`: New feature (non-breaking change which adds functionality)
- [ ] `fix`: Bug fix (non-breaking change which fixes an issue)
- [ ] `refactor`: Code refactoring without functionality changes
- [ ] `docs`: Documentation updates
- [ ] `chore`: Build system, configuration, or tooling maintenance

## 🔐 Cryptographic & Security Verification
- [ ] **No private keys stored server-side:** Recipient private keys are generated for the client and never persisted in database or logs.
- [ ] **Native crypto only:** Only `node:crypto` built-ins are used for AES-GCM, RSA-OAEP, SHA-256, and digital signatures.
- [ ] **Provenance immutability:** Provenance logs are append-only; each block links the previous `entryHash` and is signed by the server authority.
- [ ] **No secrets in code:** Secrets and credentials are only loaded from environment variables.

## 🧪 Testing Checklist
- [ ] All unit and integration tests pass: `npm test` in `backend/`
- [ ] New functionality has corresponding tests added
- [ ] Verified chain verification endpoint (`GET /api/provenance/verify`) passes with 0 issues
