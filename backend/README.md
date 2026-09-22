# SIH26237 Backend — Cryptographic Attribution & Decryption Provenance

> High-assurance Node.js & Express microservice providing multi-recipient hybrid encryption, cryptographic attribution logging, and tamper-evident signed hash-chained provenance.

---

## 🛠️ Tech Stack

- **Runtime:** Node.js 20+
- **Framework:** Express 4.x
- **Database:** MongoDB 7.x with Mongoose 8.x
- **Cryptography:** Native `node:crypto` (zero third-party crypto dependencies)
  - **AES-256-GCM:** Authenticated symmetric document encryption
  - **RSA-2048 (SPKI/PKCS#8):** Asymmetric keypair generation & management
  - **RSA-OAEP (SHA-256):** Per-recipient symmetric key wrapping
  - **SHA-256:** Document integrity hashing & canonical block hashing
  - **RSA Digital Signatures (SHA-256):** Server authority provenance block signing

---

## 📁 Directory Structure

```
backend/
├── src/
│   ├── config/
│   │   ├── env.js                # Environment config & server key loader
│   │   └── db.js                 # Mongoose connection & lifecycle
│   ├── models/
│   │   ├── User.js               # User accounts & RSA public keys
│   │   ├── Document.js           # Encrypted blob, fileHash, iv, authTag, recipientKeys
│   │   └── ProvenanceLog.js      # Sequence, prevHash, entryHash, signature, action
│   ├── services/
│   │   ├── cryptoService.js       # Native node:crypto operations
│   │   ├── provenanceService.js   # Hash-chain creation, sequential signing & verification
│   │   └── documentService.js     # Multi-recipient hybrid encryption & safe decryption
│   ├── middleware/
│   │   ├── auth.js               # JWT verification & role authorization
│   │   └── errorHandler.js       # Centralized error handler
│   ├── controllers/
│   │   ├── authController.js     # User registration, login, keys
│   │   ├── documentController.js # Upload, list, get, decrypt
│   │   └── provenanceController.js# Audit logs, chain verification, server public key
│   ├── routes/
│   │   ├── authRoutes.js         # /api/auth
│   │   ├── documentRoutes.js     # /api/documents
│   │   └── provenanceRoutes.js   # /api/provenance
│   └── server.js                 # Express application entrypoint
├── tests/
│   ├── crypto.test.js            # Unit tests for native crypto primitives
│   ├── provenance.test.js        # Hash-chain integrity & tamper detection
│   └── integration.test.js       # End-to-end API lifecycle tests
├── Dockerfile                    # Production container image
├── package.json                  # Dependencies and scripts
└── .env.example                  # Environment variables template
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Node.js 20.x or later
- MongoDB 6.x or 7.x (local service or Docker)

### 2. Installation
```bash
cd backend
npm install
```

### 3. Environment Configuration
```bash
cp .env.example .env
# Edit .env if using custom MongoDB host/credentials
```

### 4. Running the Service
```bash
# Development mode with auto-reload:
npm run dev

# Production mode:
npm start
```

### 5. Running Tests
Run all unit and integration tests using Node's native test runner:
```bash
npm test
```

---

## 📡 API Endpoints

### Health
- `GET /health` — Service health status and runtime information

### Authentication (`/api/auth`)
- `POST /api/auth/register` — Register new user, generate RSA keypair, return private key once
- `POST /api/auth/login` — Authenticate and receive JWT Bearer token
- `GET /api/auth/me` — Current user profile
- `GET /api/auth/recipients` — List available recipient public keys for encryption distribution

### Document Distribution (`/api/documents`)
- `POST /api/documents/upload` — Encrypt document with AES-256-GCM & wrap keys for designated recipients
- `GET /api/documents` — List accessible documents for the current user
- `GET /api/documents/:id` — Get document metadata and recipient's wrapped symmetric key
- `POST /api/documents/:id/decrypt` — Decrypt document with recipient's RSA private key (logs attribution)

### Provenance Audit Chain (`/api/provenance`)
- `GET /api/provenance/logs` — Query sequential provenance logs
- `GET /api/provenance/verify` — Run complete cryptographic verification across all chained records
- `GET /api/provenance/server-key` — Export server's public key for independent audit verification

---

## 🐳 Docker Deployment

Build and run the container:
```bash
docker build -t sih237-backend .
docker run -p 8000:8000 --env-file .env sih237-backend
```
