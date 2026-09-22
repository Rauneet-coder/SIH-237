# Development Guide — SIH26237

> Local setup, coding standards, testing, and workflow for new developers and AI agents joining this project.

---

## 1. Prerequisites

Install these before starting:

```bash
# Check versions
docker --version        # 26.0+
docker compose version  # v2.0+
python --version        # 3.11+
node --version          # 20.0+
go version              # 1.21+
```

### macOS Setup
```bash
brew install docker python@3.11 node go
brew install --cask docker  # Docker Desktop
```

### Ubuntu/Debian Setup
```bash
# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Python 3.11
sudo apt install python3.11 python3.11-venv python3.11-pip

# Node 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install nodejs

# Go 1.21
wget https://go.dev/dl/go1.21.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
```

---

## 2. Project Setup

### Step 1: Clone and configure
```bash
git clone <repo-url>
cd SIH_237
cp .env.example .env
# Open .env and fill in values (see .env.example for guidance)
```

### Step 2: Run the full stack
```bash
docker-compose up --build
```

First run takes ~10 minutes (builds liboqs, sets up Fabric network, installs dependencies).

### Step 3: Verify everything is running
```bash
# Backend health check
curl http://localhost:8000/health
# → {"status": "ok", "service": "SIH26237-Backend"}

# Frontend
open http://localhost:3000

# API Docs (Swagger)
open http://localhost:8000/docs

# IPFS WebUI
open http://localhost:5001/webui
```

--## 3. Backend Development (Node.js / Express / MongoDB)

### Local Dev Without Docker
```bash
cd backend

# Configure environment
cp .env.example .env

# Install dependencies
npm install

# Run dev server (hot reload with Node 20+)
npm run dev
# Server listening on http://localhost:8000
```

### Project Structure
```
backend/
├── src/
│   ├── config/
│   │   ├── env.js                # Environment settings & server authority key
│   │   └── db.js                 # Mongoose connection & lifecycle
│   ├── models/
│   │   ├── User.js               # Mongoose User model
│   │   ├── Document.js           # Mongoose Document model
│   │   └── ProvenanceLog.js      # Mongoose ProvenanceLog model
│   ├── services/
│   │   ├── cryptoService.js       # Native node:crypto operations
│   │   ├── provenanceService.js   # Hash-chain creation & audit verification
│   │   └── documentService.js     # Hybrid encryption & decryption attribution
│   ├── middleware/
│   │   ├── auth.js               # JWT verification & role middleware
│   │   └── errorHandler.js       # Centralized error handler
│   ├── controllers/
│   │   ├── authController.js     # Registration, login, user keys
│   │   ├── documentController.js # Upload, list, decrypt
│   │   └── provenanceController.js# Audit query, verification, server key
│   ├── routes/
│   │   ├── authRoutes.js         # /api/auth
│   │   ├── documentRoutes.js     # /api/documents
│   │   └── provenanceRoutes.js   # /api/provenance
│   └── server.js                 # Express application entrypoint
├── tests/
│   ├── crypto.test.js            # Unit tests for native crypto primitives
│   ├── provenance.test.js        # Hash-chain integrity & tamper tests
│   └── integration.test.js       # End-to-end API integration tests
├── Dockerfile                    # Node.js production image
└── package.json                  # Dependencies & test scripts
```

### Adding a New API Route

1. Create controller in `src/controllers/yourController.js`.
2. Create route file in `src/routes/yourRoutes.js`:
```javascript
const express = require('express');
const router = express.Router();
const yourController = require('../controllers/yourController');
const { authenticate } = require('../middleware/auth');

router.get('/', authenticate, yourController.listResources);

module.exports = router;
```

3. Mount in `src/server.js`:
```javascript
app.use('/api/your-domain', yourRoutes);
```

### Running Tests
Run all unit and integration tests using Node's native test runner:
```bash
cd backend
npm test

# Run a specific test suite
node --test tests/crypto.test.js
node --test tests/provenance.test.js
node --test tests/integration.test.js
```

### Code Quality
```bash
# Verify code syntax and style
npm test
```

---

## 4. Blockchain Development (Go / Hyperledger Fabric)

### Chaincode Structure
```
blockchain/
├── chaincode/
│   └── provenance/
│       ├── provenance.go     ← Main chaincode (smart contract)
│       ├── provenance_test.go ← Go unit tests
│       └── go.mod
├── network/
│   ├── configtx/
│   │   └── configtx.yaml     ← Channel and org configuration
│   ├── crypto-config/        ← Generated (don't edit manually)
│   └── channel-artifacts/    ← Generated genesis block, channel tx
└── scripts/
    ├── generate-crypto.sh    ← Generate all certs and keys
    ├── create-channel.sh     ← Create provchannel
    ├── join-channel.sh       ← Peers join provchannel
    └── deploy-chaincode.sh   ← Install + instantiate chaincode
```

### Running Chaincode Tests (Go)
```bash
cd blockchain/chaincode/provenance
go test ./... -v
```

### Deploying Chaincode Changes
```bash
cd blockchain/scripts

# Increment chaincode version in deploy-chaincode.sh, then:
./deploy-chaincode.sh
```

### Querying Fabric Manually
```bash
# Enter CLI container
docker exec -it fabric-cli bash

# Query by watermark
peer chaincode query \
  -C provchannel \
  -n provenance \
  -c '{"Args":["QueryByWatermark","your_watermark_id_here"]}'

# Query all events for a document
peer chaincode query \
  -C provchannel \
  -n provenance \
  -c '{"Args":["QueryByDoc","doc_hash_here"]}'
```

---

## 5. Frontend Development (Next.js / TypeScript)

### Local Dev
```bash
cd frontend
npm install
npm run dev
# → http://localhost:3000
```

### Project Structure
```
frontend/
├── app/                     ← Next.js App Router pages
│   ├── layout.tsx           ← Root layout with auth context
│   ├── page.tsx             ← Landing page
│   ├── (auth)/
│   │   ├── login/page.tsx
│   │   └── register/page.tsx
│   ├── dashboard/
│   │   ├── sender/page.tsx
│   │   ├── recipient/page.tsx
│   │   └── investigator/page.tsx
│   └── blockchain/page.tsx  ← Ledger explorer
├── components/
│   ├── ui/                  ← Reusable base components
│   ├── DocumentCard.tsx
│   ├── AttributionResult.tsx
│   └── BlockchainExplorer.tsx
└── lib/
    ├── api.ts               ← All fetch() calls to backend
    ├── crypto.ts            ← liboqs-js WebAssembly PQC
    └── types.ts             ← TypeScript interfaces
```

### API Client Pattern
```typescript
// lib/api.ts
const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api";

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: "include",  // sends httpOnly cookie with JWT
    headers: { "Content-Type": "application/json", ...options?.headers },
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail ?? "Request failed");
  }
  return res.json() as Promise<T>;
}

export const api = {
  auth: {
    login: (email: string, password: string) =>
      apiFetch("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  },
  docs: {
    list: () => apiFetch("/docs/list"),
    upload: (form: FormData) =>
      apiFetch("/docs/upload", { method: "POST", body: form }),
  },
  // ... etc
};
```

### TypeScript Standards
```typescript
// ✅ Correct — explicit types
interface DecryptionEvent {
  eventId: string;
  recipientId: string;
  watermarkId: string;
  timestamp: number;
  signatureVerified: boolean;
}

// ❌ Forbidden — any type
const data: any = response.json();  // NEVER
```

---

## 6. Environment Variables Reference

See `.env.example` for all variables. Key ones:

```env
# Security
JWT_SECRET=<secure-random-string-32-chars>     # JWT signing key

# Services
MONGODB_URI=mongodb://sih:sih_secret@mongodb:27017/sih237?authSource=admin
IPFS_HOST=ipfs
FABRIC_GATEWAY_HOST=peer0.org1.example.com

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8000/api
```

---

## 7. Git Workflow

```bash
# Feature branch naming
git checkout -b feature/provenance-verification
git checkout -b fix/auth-token-expiry
git checkout -b docs/api-reference

# Commit message format
git commit -m "feat(provenance): add full cryptographic audit verification"
git commit -m "fix(crypto): handle key unwrap failure gracefully"
git commit -m "test(api): add end-to-end decryption attribution test"

# Before pushing
npm test
```

### Branch Strategy
```
main          ← Production-ready code only
develop       ← Integration branch
feature/*     ← New features
fix/*         ← Bug fixes
docs/*        ← Documentation only changes
```

---

## 8. Debugging Common Issues

### MongoDB connection error
```bash
# Verify MongoDB is running locally
mongosh --eval "db.adminCommand('ping')"

# Or restart Docker container
docker compose restart mongodb
```

### Fabric peer connection refused
```bash
# Check peer is running
docker ps | grep peer
# Restart peer
docker-compose restart peer0
# Check logs
docker logs peer0.org1.example.com
```

### IPFS daemon not ready
```bash
docker logs ipfs_node
# If "initializing IPFS node" — wait 30 seconds, retry
curl http://localhost:5001/api/v0/id
```
