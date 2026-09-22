# System Architecture — SIH26237

> This document explains the complete system design for anyone (developer or AI) starting from scratch.

---

## 1. The Problem Being Solved

### Real-World Scenario
Imagine the Ministry of Defence sends a classified briefing to 10 generals. A few days later, that document appears on the internet. Which general leaked it?

With traditional systems: **you cannot prove it cryptographically.**

With SIH26237: **you can.**

### Root Cause of the Problem
The "broadcast-encrypt, individually-decrypt" model is efficient but non-attributable:
- One document is encrypted once
- Each of N recipients decrypts it independently
- All recipients receive identical copies
- No forensic distinction exists between copies

### Our Solution — Three Pillars

| Pillar | Mechanism | Guarantee |
|---|---|---|
| **Provenance** | Hyperledger Fabric blockchain | Who decrypted what and when — immutable |
| **Fingerprinting** | Invisible forensic watermark | Each copy is uniquely identifiable |
| **Attribution** | Watermark extraction + ledger query | Cryptographic proof of the leaker |

---

## 2. High-Level Data Flow

### 2.1 Document Upload Flow (Sender)
```
Sender uploads PDF
       ↓
[Backend] Validate file (type, size, magic bytes)
       ↓
[Backend] Generate random AES-256 key
       ↓
[Backend] Encrypt PDF with AES-256-GCM → ciphertext
       ↓
[Backend] For each recipient:
          - Encapsulate AES key using recipient's Kyber-1024 public key
          - Store KEM capsule in DB (per recipient)
       ↓
[IPFS] Store encrypted ciphertext → get Content ID (CID)
       ↓
[DB] Store: CID, sender, recipients[], docHash, timestamp
       ↓
[Frontend] Return: document ID, CID, distribution summary
```

### 2.2 Document Decryption Flow (Recipient)
```
Recipient requests decryption of document D
       ↓
[Backend] Authenticate: verify JWT → get recipientID
       ↓
[Backend] Check: is recipientID in authorized list for doc D?
       ↓
[Backend] Retrieve their KEM capsule from DB
       ↓
[Backend] Recipient decapsulates KEM capsule using their
          Kyber-1024 private key → recovers AES key
          (private key NEVER sent to server — challenge-response)
       ↓
[IPFS] Fetch encrypted ciphertext using CID
       ↓
[Backend] Decrypt ciphertext using AES-256-GCM
       ↓
[Backend] Generate unique WatermarkID:
          SHA3-256(recipientID || docCID || timestamp || nonce)
       ↓
[Watermark Engine] Embed WatermarkID invisibly into decrypted PDF
       ↓
[Backend] Request recipient to sign decryption record:
          sign({docHash, watermarkID, timestamp}) with Dilithium-3 key
       ↓
[Fabric Blockchain] Log DecryptionEvent:
          {eventID, docHash, recipientID, watermarkID,
           timestamp, dilithiumSignature, publicKey}
       ↓
[Backend] Return: watermarked PDF to recipient
```

### 2.3 Attribution Flow (Investigator)
```
Investigator uploads leaked PDF
       ↓
[Watermark Engine] Extract hidden WatermarkID from PDF
       ↓
[Fabric Blockchain] QueryByWatermark(watermarkID)
          → returns DecryptionEvent record
       ↓
[Backend] Verify Dilithium-3 signature in the record
          using stored public key
       ↓
[Backend] Generate evidence report:
          {recipient, decryptionTime, docHash, signatureValid: true}
       ↓
[Frontend] Display cryptographic attribution proof
```

---

## 3. Service Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DOCKER COMPOSE NETWORK                       │
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │ Next.js  │───▶│  Express     │───▶│  MongoDB             │  │
│  │ Frontend │    │  Backend     │    │  (metadata & chain)  │  │
│  │ :3000    │    │  :8000       │    │  :27017              │  │
│  └──────────┘    └──────┬───────┘    └──────────────────────┘  │
│                         │                                       │
│              ┌──────────┼──────────┐                           │
│              ▼          ▼          ▼                           │
│  ┌─────────────┐ ┌──────────┐ ┌───────────────────────────┐   │
│  │ IPFS Node   │ │  Fabric  │ │   Fabric Chaincode        │   │
│  │ (private)   │ │  Peer(s) │ │   (Go smart contracts)    │   │
│  │ :5001       │ │  :7051   │ │   provenance.go           │   │
│  └─────────────┘ └──────────┘ └───────────────────────────┘   │
│                         │                                       │
│                  ┌──────▼──────┐                               │
│                  │  CouchDB    │                               │
│                  │  (Fabric    │                               │
│                  │  state DB)  │                               │
│                  └─────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

### Service Responsibilities

| Service | Technology | Responsibility |
|---|---|---|
| `frontend` | Next.js 14 | UI dashboards, client-side operations |
| `backend` | Node.js / Express | Hybrid crypto, attribution logging, signed hash-chain |
| `mongodb` | MongoDB 7 | Users, keys, documents, and provenance logs |
| `ipfs` | Kubo (IPFS) | Encrypted document blob storage |
| `fabric-peer` | HLF 2.5 | Blockchain peer — validates + stores transactions |
| `fabric-orderer` | HLF 2.5 (RAFT) | Orders and finalizes blockchain transactions |
| `couchdb` | CouchDB 3.3 | Fabric world state (enables rich JSON queries) |

---

## 4. Module Breakdown (Backend)

### `src/routes/` & `src/controllers/` — Route Handlers & Controllers
```
authRoutes.js / authController.js         → /api/auth/register, /api/auth/login, /api/auth/me, /api/auth/recipients
documentRoutes.js / documentController.js → /api/documents/upload, /api/documents, /api/documents/:id, /api/documents/:id/decrypt
provenanceRoutes.js / provenanceController.js → /api/provenance/logs, /api/provenance/verify, /api/provenance/server-key
```

### `src/services/` — Business & Cryptographic Logic
```
cryptoService.js     → AES-256-GCM, RSA-2048 keygen, RSA-OAEP key wrapping, SHA-256, RSA digital signing
provenanceService.js → Sequential signed hash-chain generation & full audit verification
documentService.js   → Multi-recipient hybrid encryption & decryption with attribution logging
```

### `src/config/` & `src/middleware/` — Infrastructure
```
config/env.js        → Environment variables & server authority keypair loader
config/db.js         → Mongoose MongoDB connection pool
middleware/auth.js   → JWT Bearer authentication & role-based authorization
middleware/errorHandler.js → Centralized JSON error formatting
```

### `src/models/` — Mongoose Schemas
```
User.js              → User schema (username, email, password, role, publicKey, isActive)
Document.js          → Document schema (title, senderId, fileHash, encryptedBlob, iv, authTag, recipientKeys)
ProvenanceLog.js     → ProvenanceLog schema (sequenceNumber, docId, recipientId, action, status, prevHash, entryHash, signature)
```

---

## 5. Key Design Decisions

### 5.1 Why Hybrid Encryption?
Post-quantum KEM (Kyber) is used to wrap an AES key, not to encrypt the document directly. This is the NIST-approved pattern because:
- Kyber is designed for key encapsulation, not bulk encryption
- AES-256-GCM is orders of magnitude faster for large data
- Each recipient gets their own KEM capsule wrapping the same AES key

### 5.2 Why Watermark at Decryption, Not Upload?
If the watermark were embedded at upload time, all recipients would get the same watermark — defeating the purpose. By watermarking at decryption time, each session produces a unique fingerprint.

### 5.3 Why Hyperledger Fabric?
- **Permissioned:** Only authorized nodes/organizations can join
- **No tokens/gas:** No public coin — suitable for government use
- **Private transactions:** Data stays within the consortium
- **Append-only by design:** Smart contracts control what operations are allowed
- **CouchDB integration:** Enables SQL-like queries on JSON state

### 5.4 Why IPFS for Document Storage?
- **Content addressing:** The CID is a hash of the content — tampering changes the CID
- **Decentralized:** No single point of storage failure
- **Private node:** Running our own node means no public exposure

### 5.5 Why Private Keys Never Touch the Server?
If the server holds private keys, a compromised server means all documents are compromised. Our threat model treats the server as potentially adversarial — only public keys are stored there.

---

## 6. Data Models

### DecryptionEvent (Blockchain Ledger — CouchDB)
```json
{
  "eventId": "evt_sha256_of_all_fields",
  "docHash": "sha3_256_of_original_doc",
  "docCID": "Qm...",
  "recipientId": "user_uuid",
  "recipientEmail": "general.sharma@mod.gov.in",
  "watermarkId": "sha3_256(recipientId||docCID||ts||nonce)",
  "timestamp": 1727018000,
  "dilithiumSignature": "base64_encoded_signature",
  "dilithiumPublicKey": "base64_encoded_pubkey",
  "signatureValid": true
}
```

### Document (PostgreSQL)
```sql
documents (
  id          UUID PRIMARY KEY,
  cid         TEXT UNIQUE,        -- IPFS content ID
  doc_hash    TEXT,               -- SHA3-256 of original
  sender_id   UUID REFERENCES users(id),
  title       TEXT,
  created_at  TIMESTAMP,
  size_bytes  INTEGER
)
```

### KEMCapsule (PostgreSQL — per recipient)
```sql
kem_capsules (
  id           UUID PRIMARY KEY,
  document_id  UUID REFERENCES documents(id),
  recipient_id UUID REFERENCES users(id),
  capsule      BYTEA,   -- Kyber KEM capsule (encapsulated AES key)
  created_at   TIMESTAMP
)
```

---

## 7. Security Boundaries

```
TRUST BOUNDARY 1: Public Internet → Docker Network
  → Nginx reverse proxy, HTTPS termination, rate limiting

TRUST BOUNDARY 2: Frontend → Backend
  → JWT authentication on every request
  → Input validation and sanitization

TRUST BOUNDARY 3: Backend → Blockchain
  → Fabric MSP certificate authentication
  → TLS between peer and application

TRUST BOUNDARY 4: Private Keys
  → NEVER cross into the server environment
  → Live only in the user's browser or hardware token
```
