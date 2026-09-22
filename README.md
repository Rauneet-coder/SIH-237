# SIH26237 — Cryptographic Attribution & Immutable Decryption Provenance System

> **Ministry of Defence | Smart India Hackathon 2026 | PS ID: SIH26237**  
> Theme: Blockchain & Cybersecurity | Category: Software | Deadline: 30 September 2026

---

## 🔍 What This Project Does

When a classified document is distributed to multiple authorized recipients, anyone could leak it — and traditional systems cannot prove **who** did it. This system solves that by:

1. **Encrypting documents** with post-quantum cryptography (Kyber-1024)
2. **Injecting an invisible forensic watermark** unique to each recipient at decryption time
3. **Logging every decryption event immutably** on a private Hyperledger Fabric blockchain
4. **Enabling cryptographic attribution** — if a document leaks, the system can extract the watermark and prove cryptographically who decrypted it

---

## 🏗️ Architecture Overview

```
Sender → Encrypts Doc (AES-256-GCM + Kyber KEM) → IPFS Storage
                                                         ↓
                            Recipient requests decryption
                                                         ↓
                    System injects unique invisible watermark
                                                         ↓
              Decryption event logged on Hyperledger Fabric
               (signed by recipient's Dilithium-3 PQ key)
                                                         ↓
              If leaked → extract watermark → query blockchain
                        → cryptographic attribution proof
```

---

## 📁 Repository Structure

```
SIH_237/
├── backend/               # Python FastAPI microservice
│   ├── app/
│   │   ├── api/           # Route handlers
│   │   ├── core/          # Config, DB, crypto utilities
│   │   ├── models/        # SQLAlchemy ORM models
│   │   └── services/      # Business logic
│   └── tests/             # Pytest unit + integration tests
├── blockchain/            # Hyperledger Fabric
│   ├── chaincode/         # Go chaincode (smart contracts)
│   ├── network/           # Fabric network config
│   └── scripts/           # Deploy/invoke scripts
├── frontend/              # Next.js 14 App Router (TypeScript)
│   ├── app/               # Pages and layouts
│   ├── components/        # Reusable UI components
│   └── lib/               # Client-side PQC utils (liboqs-js)
├── docs/                  # Full knowledge base (read these first!)
│   ├── ARCHITECTURE.md    # System design deep-dive
│   ├── CRYPTOGRAPHY.md    # PQC algorithms explained
│   ├── BLOCKCHAIN.md      # Hyperledger Fabric guide
│   ├── WATERMARKING.md    # Forensic watermarking explained
│   ├── API.md             # All API endpoints
│   ├── SECURITY.md        # Threat model & security design
│   └── DEVELOPMENT.md     # Dev setup & workflow
├── AGENTS.md              # AI agent rules (auto-loaded)
├── requirement.md         # Full SRS document
├── docker-compose.yml     # Full stack orchestration
└── .env.example           # Environment variable template
```

---

## 🚀 Quick Start

### Prerequisites
- Docker 26+ and Docker Compose v2
- Node.js 20+ (for frontend dev)
- Python 3.11+ (for backend dev)
- Go 1.21+ (for chaincode dev)

### Run the Full Stack
```bash
# 1. Clone the repo
git clone <repo-url> && cd SIH_237

# 2. Set up environment
cp .env.example .env
# Edit .env with your values

# 3. Start all services
docker-compose up --build

# 4. Access services
# Frontend:        http://localhost:3000
# API + Swagger:   http://localhost:8000/docs
# IPFS Dashboard:  http://localhost:5001/webui
```

### Run Tests
```bash
# Backend unit tests
cd backend && pip install -r requirements.txt
pytest tests/ -v

# Go chaincode tests
cd blockchain/chaincode/provenance && go test ./...
```

---

## 📚 Documentation Index

| Document | What It Teaches |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Full system design, data flow, service interactions |
| [CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) | PQC algorithms, Kyber, Dilithium, AES-GCM from scratch |
| [BLOCKCHAIN.md](docs/BLOCKCHAIN.md) | Hyperledger Fabric, chaincode, CouchDB queries |
| [WATERMARKING.md](docs/WATERMARKING.md) | Invisible watermark embedding and extraction |
| [API.md](docs/API.md) | All REST endpoints with request/response schemas |
| [SECURITY.md](docs/SECURITY.md) | Threat model, attack surfaces, mitigations |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Local dev setup, coding standards, CI/CD |
| [requirement.md](requirement.md) | Formal SRS (functional + non-functional requirements) |

---

## 🔑 Key Technologies

| Technology | Version | Role |
|---|---|---|
| FastAPI (Python) | 0.111 | REST API backend |
| liboqs-python | 0.10.1 | Post-quantum cryptography |
| PyMuPDF | 1.24.5 | PDF watermark injection |
| Hyperledger Fabric | 2.5.x | Private blockchain |
| IPFS (Kubo) | 0.28 | Encrypted document storage |
| Next.js | 14.x | Frontend dashboard |
| PostgreSQL | 16 | Application metadata DB |
| CouchDB | 3.3 | Fabric state database |
| Docker Compose | v2 | Full stack orchestration |

---

## 👥 Team

> SIH26237 — Ministry of Defence, Government of India

---

## ⚠️ Important Notes for Developers & AI Agents

- **Read `AGENTS.md` first** — it contains non-negotiable coding rules
- **Never use RSA or ECDSA** — this is a post-quantum system
- **Never store private keys server-side** — architectural non-starter
- **Never use public blockchains** — Hyperledger Fabric only
- **Read `docs/CRYPTOGRAPHY.md`** before touching any crypto code
