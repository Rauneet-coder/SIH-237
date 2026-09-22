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

---

## 3. Backend Development (Python / FastAPI)

### Local Dev Without Docker
```bash
cd backend

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies (liboqs requires system lib)
# On Ubuntu: sudo apt install cmake ninja-build libssl-dev
pip install -r requirements.txt

# Run dev server (hot reload)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Project Structure
```
backend/app/
├── main.py              ← FastAPI app, middleware, router registration
├── api/
│   ├── auth.py          ← Registration, login, refresh
│   ├── kms.py           ← Key management endpoints
│   ├── documents.py     ← Upload, list, decrypt
│   ├── blockchain.py    ← Ledger query endpoints
│   └── attribution.py  ← Leaked doc analysis
├── core/
│   ├── config.py        ← All settings (pydantic-settings)
│   ├── database.py      ← SQLAlchemy async engine
│   ├── security.py      ← JWT, password hashing
│   └── crypto.py        ← Low-level liboqs bindings
├── models/
│   ├── user.py          ← User, Role ORM models
│   ├── keypair.py       ← PublicKey model
│   ├── document.py      ← Document, KEMCapsule models
│   └── session.py       ← DecryptionSession model
└── services/
    ├── crypto_service.py    ← Kyber, Dilithium, AES-GCM
    ├── watermark_service.py ← PDF watermark embed/extract
    ├── fabric_service.py    ← Hyperledger Fabric gateway
    ├── ipfs_service.py      ← IPFS upload/download
    ├── document_service.py  ← Document lifecycle
    └── attribution_service.py ← Attribution engine
```

### Adding a New API Route

1. Create route file in `backend/app/api/your_domain.py`:
```python
# Standard library
from typing import List

# Third-party
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

# Local
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.services import your_service

router = APIRouter()


@router.get("/", summary="List resources")
async def list_resources(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[dict]:
    """List all resources for the current user."""
    return await your_service.get_all(db, current_user.id)
```

2. Register in `backend/app/main.py`:
```python
from app.api import your_domain
app.include_router(your_domain.router, prefix="/api/your-domain", tags=["Your Domain"])
```

### Running Tests
```bash
cd backend

# All tests
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=app --cov-report=term-missing

# Single test file
pytest tests/test_watermark.py -v

# Single test function
pytest tests/test_crypto.py::test_kyber_roundtrip -v
```

### Code Quality
```bash
# Format with black
black app/ tests/

# Lint with flake8
flake8 app/ tests/ --max-line-length 100

# Type check with mypy
mypy app/
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
SECRET_KEY=<256-bit-random-hex>             # JWT signing key

# Services
DATABASE_URL=postgresql+asyncpg://sih:pass@postgres:5432/sih237
IPFS_HOST=ipfs
FABRIC_GATEWAY_HOST=peer0.org1.example.com

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8000/api
```

---

## 7. Git Workflow

```bash
# Feature branch naming
git checkout -b feature/watermark-extraction
git checkout -b fix/kyber-keygen-error
git checkout -b docs/api-reference

# Commit message format
git commit -m "feat(watermark): add invisible text layer embedding"
git commit -m "fix(crypto): handle Kyber decapsulation failure gracefully"
git commit -m "test(attribution): add roundtrip watermark test"

# Before pushing
black app/ && flake8 app/ && pytest tests/ -v
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

### liboqs not found
```bash
# liboqs C library must be installed before pip install
# In Docker: handled automatically
# Local (Ubuntu):
sudo apt install cmake ninja-build libssl-dev
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja .. && ninja && sudo ninja install
pip install liboqs-python
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

### PostgreSQL migration needed
```bash
cd backend
alembic upgrade head
```
