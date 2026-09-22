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
├── backend/               # Python FastAPI microservice
│   ├── app/
│   │   ├── api/           # Route handlers (one file per domain)
│   │   ├── core/          # Config, database, security utilities
│   │   ├── models/        # SQLAlchemy ORM models
│   │   └── services/      # Business logic (crypto, watermark, fabric)
│   └── tests/             # Pytest unit + integration tests
├── blockchain/            # Hyperledger Fabric
│   ├── chaincode/         # Go chaincode (smart contracts)
│   ├── network/           # Fabric network config files
│   └── scripts/           # Deploy, invoke, query scripts
├── frontend/              # Next.js 14 App Router (TypeScript)
│   ├── app/               # Pages and layouts
│   ├── components/        # Reusable UI components
│   └── lib/               # Client-side crypto utilities (liboqs-js)
├── docs/                  # Architecture diagrams, API specs
├── requirement.md         # Software Requirements Specification (SRS)
├── docker-compose.yml     # Full stack orchestration
└── AGENTS.md              # ← This file
```

Always place new files in the correct module directory. Never create files in the project root unless they are top-level config files (e.g., `docker-compose.yml`, `.env.example`, `README.md`).

---

## 🧠 Architecture Rules

1. **Microservice boundaries are strict.** Backend, blockchain, and frontend are separate services. Do not mix concerns across service boundaries.
2. **All inter-service communication must go through the FastAPI REST layer.** The frontend never talks directly to Fabric or IPFS.
3. **Every new API route must be placed in `backend/app/api/`.** Create a dedicated file per domain (e.g., `kms.py`, `documents.py`).
4. **Business logic belongs in `backend/app/services/`.** Route handlers in `api/` should be thin — they call services, not implement logic.
5. **Database models go in `backend/app/models/`.** Use SQLAlchemy declarative base. One file per model group.
6. **Config values must use `backend/app/core/config.py`.** Never hardcode hostnames, ports, secrets, or paths in application code.
7. **Fabric chaincode functions:** `LogDecryption`, `QueryByWatermark`, `QueryByRecipient`, `QueryByDoc`. Do not add update/delete functions — the ledger is append-only by design.

---

## 🔐 Cryptographic Rules (CRITICAL)

These rules are non-negotiable. Violating them breaks the security guarantees of the system.

1. **NEVER use RSA, ECDSA, or any classical asymmetric cryptography** for primary operations (encryption or signing). Use post-quantum algorithms only.
2. **Encryption:** Use `Kyber-1024` (ML-KEM / FIPS 203) for key encapsulation via `liboqs-python`.
3. **Signing:** Use `Dilithium-3` (ML-DSA / FIPS 204) for digital signatures via `liboqs-python`.
4. **Document encryption:** Use `AES-256-GCM` (symmetric). The AES key is wrapped per-recipient using Kyber KEM.
5. **Watermark ID generation:** Always use `SHA3-256(recipientID || docCID || timestamp || nonce)`.
6. **NEVER store private keys server-side.** Private keys are generated for the user and must only be held by the user. The server stores only public keys.
7. **Random values:** Always use `secrets.token_bytes()` or `os.urandom()` for cryptographic nonces. Never use `random` module for security-sensitive operations.
8. **All crypto operations must be in `backend/app/core/crypto.py` or `backend/app/services/crypto_service.py`.** Do not scatter crypto code across route handlers.

---

## 🔗 Blockchain Rules

1. **Use Hyperledger Fabric only.** Do NOT suggest or use Ethereum, Polygon, Solana, or any public blockchain.
2. **Chaincode is written in Go.** Do not write chaincode in Node.js or Java.
3. **Chaincode must be stateless per-invocation.** Use the Fabric stub for all state reads/writes.
4. **All ledger writes are final.** The chaincode has no `UpdateEvent` or `DeleteEvent` function. Do not add one.
5. **Use CouchDB** as the Fabric state database to enable rich JSON queries.
6. **Fabric interaction from Python** uses the `fabric-sdk-py` or the Fabric Gateway REST client. Do not call Fabric binaries directly from application code.

---

## 🎨 Watermarking Rules

1. **Watermarks are injected at decryption time only,** not at upload time. This ensures uniqueness per decryption event.
2. **Use `PyMuPDF` (fitz)** for all PDF manipulation — do not use `reportlab` or `pypdf2` for watermarking.
3. **Watermarks must be invisible.** Use white-on-white text layers or metadata embedding. Never produce visible text/stamps on the document.
4. **Each watermark is unique per decryption session.** Two recipients decrypting the same document get different watermarks.
5. **The watermark extraction function must be the inverse of the embedding function.** Test both together in `tests/test_watermark.py`.

---

## 🐍 Python / Backend Standards

1. **Python version:** 3.11+
2. **Follow PEP 8.** Use `black` for formatting and `flake8` for linting.
3. **Use `async/await` throughout.** All route handlers and database calls must be asynchronous.
4. **Use type hints on all function signatures.** No untyped functions.
5. **Use Pydantic v2 models** for all request/response schemas. Place them alongside route files or in a `schemas/` folder.
6. **Error handling:** Use FastAPI's `HTTPException` for API errors. Never let unhandled exceptions reach the client.
7. **Environment variables:** All config is loaded via `app/core/config.py` (pydantic-settings). Never use `os.environ.get()` directly in route handlers.
8. **Tests:** Place all tests in `backend/tests/`. Use `pytest` with `pytest-asyncio`. Test all crypto primitives independently.

### Import Order (follow strictly)
```python
# 1. Standard library
import os
import hashlib

# 2. Third-party
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

# 3. Local app imports
from app.core.config import settings
from app.models.user import User
```

---

## 🌐 Frontend Standards (Next.js / TypeScript)

1. **Use Next.js 14 App Router.** Do not use the Pages Router.
2. **TypeScript strict mode is enabled.** No `any` types without explicit justification.
3. **Use `fetch` with `async/await`** for API calls. Wrap in a `lib/api.ts` client module.
4. **Client-side PQC operations** use `liboqs-js` (WebAssembly). Import only in `'use client'` components.
5. **State management:** Use React `useState` / `useContext` for local state. Do not add Redux unless complexity demands it.
6. **Styling:** Use CSS Modules (`.module.css`) or Tailwind CSS. No inline styles except for dynamic values.
7. **All pages must have proper `<title>` and `<meta description>` tags** set via Next.js `metadata` export.
8. **Authentication:** Store JWT token in an `httpOnly` cookie. Never in `localStorage`.

---

## 🐳 Docker / Infrastructure Rules

1. **Every service must have a `Dockerfile`.**
2. **`docker-compose.yml` at the project root** is the single source of truth for running the full stack.
3. **Use named Docker volumes** for persistent data (PostgreSQL, IPFS, CouchDB). Never mount raw paths for database data.
4. **Services communicate by Docker service name** (e.g., `http://backend:8000`), not `localhost`.
5. **Secrets go in `.env` file.** Provide `.env.example` with all required keys and placeholder values. Never commit `.env` to version control.
6. **Health checks must be defined** for backend, postgres, and fabric peer services in `docker-compose.yml`.

---

## 📝 Documentation Rules

1. **All new public functions must have a docstring** explaining purpose, parameters, and return value.
2. **Update `requirement.md`** if any new functional or non-functional requirement is discovered during development.
3. **API changes must be reflected in the auto-generated Swagger docs** at `/docs`. Keep route descriptions accurate.
4. **`README.md`** at the project root must always have up-to-date setup and run instructions.

---

## 🔒 Security Constraints (Never Violate)

- ❌ Never log private keys, AES keys, or decrypted document content to console or log files.
- ❌ Never return raw decrypted document bytes without watermarking.
- ❌ Never expose IPFS or PostgreSQL ports outside the Docker network.
- ❌ Never add a blockchain record deletion or update endpoint.
- ❌ Never use `eval()`, `exec()`, or dynamic code execution anywhere.
- ❌ Never trust client-supplied file types — always validate server-side.
- ✅ Always validate JWT on every protected route using `Depends(get_current_user)`.
- ✅ Always sanitize and validate uploaded file content (magic bytes check, size limit).
- ✅ Always use parameterized queries via SQLAlchemy ORM — no raw SQL string interpolation.

---

## ✅ Definition of Done (Per Feature)

A feature is considered complete when:
- [ ] Code is written and follows all rules in this file
- [ ] Unit tests are written and passing (`pytest`)
- [ ] API endpoint is documented in Swagger (`/docs`)
- [ ] Docker Compose brings up the service without errors
- [ ] No private keys, secrets, or sensitive data appear in logs

---

## 🚀 Quick Start Commands

```bash
# Start full stack
docker-compose up --build

# Run backend tests
cd backend && pytest tests/ -v

# Run chaincode tests (Go)
cd blockchain/chaincode/provenance && go test ./...

# Access services
# API Docs:        http://localhost:8000/docs
# Frontend:        http://localhost:3000
# IPFS Dashboard:  http://localhost:5001/webui
```
