# SIH26237 — Cryptographic Attribution & Immutable Decryption Provenance System

> **Ministry of Defence | Smart India Hackathon 2026 | PS ID: SIH26237**  
> Theme: Blockchain & Cybersecurity | Category: Software | Deadline: 30 September 2026

---

## 🔍 What This Project Does

When a classified document is distributed to multiple authorized recipients, anyone could leak it — and traditional systems cannot prove **who** did it. This system solves that by:

1. **Multi-Recipient Hybrid Encryption:** Document encrypted with AES-256-GCM; symmetric key encrypted individually for each recipient using their RSA public key.
2. **Attribution & Decryption Logging:** Every decryption attempt (success or failure) is logged with recipient ID, document hash, and timestamp.
3. **Tamper-Evident Signed Provenance Hash-Chain:** Immutable audit ledger where every block cryptographically chains the previous block's SHA-256 hash and is signed with the server's private authority key.
4. **Cryptographic Chain Verification:** An independent verification service that walks the entire chain, recomputes hashes, verifies digital signatures, and detects any alteration or deletion.

---

## 🏗️ Architecture Overview

```
Sender → Encrypts Doc (AES-256-GCM + RSA-OAEP per recipient) → Secure Storage (MongoDB/IPFS)
                                                         ↓
                            Recipient requests decryption with private key
                                                         ↓
                         System logs DECRYPT_ATTEMPT in provenance chain
                                                         ↓
                   Key unwrapped & decrypted → Hash verified (SHA-256)
                                                         ↓
                 DECRYPT_SUCCESS / DECRYPT_FAILURE logged in signed hash-chain
                                                         ↓
             Independent auditors call /api/provenance/verify to prove chain integrity
```

---

## 📁 Repository Structure

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
│   └── Dockerfile             # Frontend container
├── docs/                      # Technical guides & specifications
├── AGENTS.md                  # Development & AI rules
├── requirement.md             # Formal SRS document
├── docker-compose.yml         # Full stack orchestration
└── .env.example               # Environment variable template
```

---

## 🚀 Quick Start

### Prerequisites
- Docker 26+ and Docker Compose v2 (for containerized setup)
- Node.js 20+ (for backend and frontend development)
- MongoDB 6+ or 7+ (local or containerized)

### Local Development Setup

#### 1. Backend Setup
```bash
cd backend
cp .env.example .env
npm install
npm run dev
# Server running at http://localhost:8000
```

#### 2. Run Backend Tests
```bash
cd backend
npm test
# Runs 23/23 unit and integration tests (crypto, provenance hash-chain, REST API)
```

### Full Stack via Docker Compose
```bash
# 1. Clone repository
git clone <repo-url> && cd SIH_237

# 2. Configure environment
cp .env.example .env

# 3. Start services
docker compose up --build

# 4. Access services
# Frontend:            http://localhost:3000
# Backend API:         http://localhost:8000/health
# Chain Verification:  http://localhost:8000/api/provenance/verify
```

---

## 🔑 Key Technologies

| Technology | Version | Role |
|---|---|---|
| Node.js & Express | 20+ / 4.x | REST API backend service |
| node:crypto | Built-in | AES-256-GCM, RSA-OAEP, SHA-256, RSA signatures |
| MongoDB & Mongoose | 7.x / 8.x | Documents, users, and provenance audit storage |
| Next.js | 14.x | Frontend dashboard & client interface |
| Docker & Docker Compose | v2 | Container orchestration |

---

## 📡 Core API Summary

- `GET /health` — Service health status
- `POST /api/auth/register` — User registration with RSA keypair generation
- `POST /api/auth/login` — User authentication with JWT issuance
- `GET /api/auth/recipients` — List available recipient public keys
- `POST /api/documents/upload` — Multi-recipient hybrid document encryption & upload
- `GET /api/documents` — List accessible encrypted documents
- `POST /api/documents/:id/decrypt` — Decrypt document with recipient private key (with provenance logging)
- `GET /api/provenance/logs` — Query sequential audit logs
- `GET /api/provenance/verify` — Cryptographic hash-chain & signature verification
- `GET /api/provenance/server-key` — Export server's public key for external verification

---

## 👥 Team & Project Info

> **SIH26237** — Ministry of Defence, Government of India  
> Smart India Hackathon 2026
