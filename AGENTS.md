# AGENTS.md — SIH26237 Project Agent Rules

> This file is automatically loaded by the Antigravity IDE agent for all work
> done inside this workspace. It defines coding standards, architectural rules,
> security constraints, and behavioral guidelines specific to this project.

---

## 📌 Project Identity

- **Project:** SIH26237 — Cryptographic Attribution & Immutable Decryption Provenance System
- **Organization:** Ministry of Defence, Government of India
- **Hackathon:** Smart India Hackathon (SIH) 2026
- **Theme:** Blockchain & Cybersecurity
- **Deadline:** 30 September 2026
- **PS ID:** SIH26237

---

## 🗂️ Project Structure

```
SIH_237/
├── backend/                   # Node.js + Express microservice
│   ├── src/
│   │   ├── config/            # DB (Mongoose) & Environment config
│   │   ├── controllers/       # Auth, Document & Provenance controllers
│   │   ├── middleware/        # JWT auth & error handling
│   │   ├── models/            # User, Document, ProvenanceLog Mongoose models
│   │   ├── routes/            # REST API route declarations
│   │   ├── services/          # cryptoService, provenanceService, documentService
│   │   └── server.js          # Express app entrypoint
│   ├── tests/                 # Unit & integration tests (node:test)
│   ├── package.json           # Dependencies & test scripts
│   ├── Dockerfile             # Production Node.js container
│   └── README.md              # Backend detailed documentation
├── frontend/                  # Next.js 14 App Router (TypeScript)
│   ├── app/                   # Pages and layouts
│   ├── components/            # Reusable UI components
│   └── lib/                   # Client utilities
├── docs/                      # Technical guides & specs
├── requirement.md             # Software Requirements Specification (SRS)
├── docker-compose.yml         # Full stack orchestration
└── AGENTS.md                  # ← This file
```

Always place new files in the correct module directory. Never create files in the project root unless they are top-level config files (e.g., `docker-compose.yml`, `.env.example`, `README.md`).

---

## 🧠 Architecture Rules

1. **Microservice boundaries are strict.** Backend, frontend, and database are separate services. Do not mix concerns across service boundaries.
2. **All inter-service communication must go through the Express REST layer.**
3. **Route handlers in `src/routes/` and `src/controllers/` should be thin.** Business and crypto logic belong in `src/services/`.
4. **Database models go in `src/models/`.** Use Mongoose schemas with strict types and timestamps.
5. **Config values must use `src/config/env.js`.** Never hardcode secrets, ports, or credentials in application code.
6. **Provenance ledger is append-only by design.** There are no update or delete functions for provenance records.

---

## 🔐 Cryptographic Rules (CRITICAL)

These rules are non-negotiable. Violating them breaks the security guarantees of the system.

1. **Native Cryptography Only:** Use Node.js built-in `node:crypto` for all cryptographic operations. Do not introduce third-party crypto libraries unless built-in genuinely cannot support a requirement.
2. **Document Encryption:** Use `AES-256-GCM` with a fresh 32-byte key and 12-byte IV per document. Always verify the 16-byte authentication tag upon decryption.
3. **Hybrid Key Encapsulation:** Wrap the document AES symmetric key individually per recipient using `RSA-OAEP` with `SHA-256`.
4. **Provenance Log Hashing:** Every provenance block must hash the canonical representation of sequence, prevHash, docId, recipientId, action, status, and timestamp using `SHA-256`.
5. **Digital Signatures:** Every provenance block's entryHash must be digitally signed by the server's private authority key using `RSA-SHA256`.
6. **NEVER store private keys server-side.** Recipient private keys are generated for the user and must only be held by the user. The server stores only public keys.
7. **Random values:** Always use `crypto.randomBytes()` for keys and IVs. Never use `Math.random()`.
8. **All crypto operations must reside in `src/services/cryptoService.js`.**

---

## 📜 Provenance & Audit Rules

1. **Immutable Chain:** Entries are indexed sequentially starting at 1. Genesis block has a `prevHash` of 64 zeros (`0000000000000000000000000000000000000000000000000000000000000000`).
2. **Decryption Attribution:** Every decryption attempt must be logged immediately. If unauthorized or unwrap fails, log `DECRYPT_FAILURE`. If successful, log `DECRYPT_SUCCESS`.
3. **Independent Verification:** The system must provide a verification service (`/api/provenance/verify`) that recalculates all hashes and verifies digital signatures across the entire history.

---

## ⚡ Node.js / Backend Standards

1. **Runtime:** Node.js 20+
2. **Code style:** Clean, modular CommonJS or ES modules with meaningful variable names.
3. **Use `async/await` throughout.** All controller handlers and database calls must be asynchronous.
4. **Validation:** Validate all input parameters before processing.
5. **Error handling:** Use the centralized `errorHandler` middleware. Never leak internal stack traces to client responses in production.
6. **Tests:** Place all tests in `backend/tests/`. Use Node's built-in `node:test` runner.

---

## 🌐 Frontend Standards (Next.js / TypeScript)

1. **Use Next.js 14 App Router.**
2. **TypeScript strict mode is enabled.**
3. **Use `fetch` with `async/await`** for API calls to the Express backend.
4. **Authentication:** Store JWT tokens securely.

---

## 🐳 Docker / Infrastructure Rules

1. **Every service must have a `Dockerfile`.**
2. **`docker-compose.yml` at the project root** orchestrates the full stack (backend, mongodb, frontend).
3. **Use named Docker volumes** for persistent data (`mongodb-data`).
4. **Secrets go in `.env` file.** Provide `.env.example` with placeholder values. Never commit `.env` to version control.

---

## 🔒 Security Constraints (Never Violate)

- ❌ Never log private keys, AES keys, or decrypted document content to console or log files.
- ❌ Never return raw decrypted document bytes without logging provenance attribution.
- ❌ Never add a provenance record deletion or update endpoint.
- ❌ Never use `eval()`, `exec()`, or dynamic code execution anywhere.
- ❌ Never trust client-supplied file types — validate server-side.
- ✅ Always validate JWT on protected routes using `authenticate` middleware.
- ✅ Always use parameterized queries via Mongoose schemas.

---

## 🚀 Quick Start Commands

```bash
# Install and run backend
cd backend
npm install
npm run dev

# Run backend tests (23/23 tests)
npm test

# Access services
# Backend Health: http://localhost:8000/health
# Chain Verify:   http://localhost:8000/api/provenance/verify
```
