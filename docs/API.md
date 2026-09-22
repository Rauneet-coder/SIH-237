# API Reference — SIH26237

> Complete REST API documentation. The FastAPI backend auto-generates interactive Swagger docs at `http://localhost:8000/docs`.

---

## Base URL
```
Development: http://localhost:8000/api
Production:  https://your-domain.com/api
```

## Authentication
All endpoints (except `/auth/register` and `/auth/login`) require a valid JWT:
```
Authorization: Bearer <access_token>
```

---

## 1. Authentication — `/api/auth`

### POST `/api/auth/register`
Register a new user. Public keys are stored; private keys are returned once and never stored.

**Request:**
```json
{
  "username": "general_sharma",
  "email": "sharma@mod.gov.in",
  "password": "SecurePass123!",
  "role": "recipient"  // "sender" | "recipient" | "investigator" | "admin"
}
```

**Response `201`:**
```json
{
  "user_id": "uuid-v4",
  "username": "general_sharma",
  "email": "sharma@mod.gov.in",
  "role": "recipient",
  "keypairs": {
    "kyber": {
      "public_key": "base64_kyber_public_key",
      "private_key": "base64_kyber_private_key"  // ⚠️ SAVE THIS — never sent again
    },
    "dilithium": {
      "public_key": "base64_dilithium_public_key",
      "private_key": "base64_dilithium_private_key"  // ⚠️ SAVE THIS — never sent again
    }
  }
}
```
> **CRITICAL:** Private keys are returned only once at registration. The server immediately discards them. The user must save them securely.

---

### POST `/api/auth/login`
```json
// Request
{ "email": "sharma@mod.gov.in", "password": "SecurePass123!" }

// Response 200
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": { "id": "uuid", "username": "general_sharma", "role": "recipient" }
}
```

### POST `/api/auth/refresh`
```json
// Request (with valid token in Authorization header)
{}

// Response 200
{ "access_token": "new_token...", "expires_in": 3600 }
```

---

## 2. Key Management — `/api/kms`

### GET `/api/kms/my-keys`
Returns the current user's registered public keys.
```json
// Response 200
{
  "user_id": "uuid",
  "kyber_public_key": "base64...",
  "dilithium_public_key": "base64..."
}
```

### POST `/api/kms/register-pubkey`
Register new public keys (e.g., after key rotation).
```json
// Request
{
  "kyber_public_key": "base64_new_kyber_pubkey",
  "dilithium_public_key": "base64_new_dilithium_pubkey"
}
// Response 200
{ "message": "Public keys updated successfully" }
```

### GET `/api/kms/users`
List all users and their public keys (sender role required).
```json
// Response 200
[
  {
    "user_id": "uuid-1",
    "username": "general_sharma",
    "email": "sharma@mod.gov.in",
    "kyber_public_key": "base64..."
  }
]
```

---

## 3. Documents — `/api/docs`

### POST `/api/docs/upload`
Upload and encrypt a document. Sender role required.

**Request:** `multipart/form-data`
```
file: <PDF binary>
title: "Operation XYZ Briefing"
recipient_ids: ["uuid-1", "uuid-2", "uuid-3"]  (JSON array as form field)
```

**Response `201`:**
```json
{
  "document_id": "uuid",
  "title": "Operation XYZ Briefing",
  "cid": "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco",
  "doc_hash": "sha3_256_of_original",
  "recipients": ["uuid-1", "uuid-2", "uuid-3"],
  "created_at": "2026-09-22T18:00:00Z",
  "size_bytes": 204800
}
```

---

### GET `/api/docs/list`
List documents accessible to the current user (sent or received).

**Response `200`:**
```json
[
  {
    "document_id": "uuid",
    "title": "Operation XYZ Briefing",
    "sender": { "id": "uuid", "name": "Col. Verma" },
    "created_at": "2026-09-22T18:00:00Z",
    "size_bytes": 204800,
    "decrypted": false
  }
]
```

---

### POST `/api/docs/decrypt/{document_id}`
Decrypt and receive a watermarked copy of the document. Recipient role; only authorized recipients.

**Request:**
```json
{
  "dilithium_signature": "base64_signature_of_intent_record",
  "kyber_decapsulated_key": "base64_32_byte_aes_key"
}
```
> The client uses their local Dilithium private key to sign the intent, and their local Kyber private key to decapsulate the AES key from the stored capsule.

**Response `200`:** Binary PDF (application/pdf)
```
Content-Type: application/pdf
Content-Disposition: attachment; filename="op_xyz_briefing_watermarked.pdf"
[binary PDF data — watermarked copy]
```
> Side effects: Watermark embedded, blockchain event logged.

---

### GET `/api/docs/{document_id}`
Get document metadata (no decryption).
```json
{
  "document_id": "uuid",
  "title": "Operation XYZ Briefing",
  "cid": "Qm...",
  "doc_hash": "sha3_256...",
  "sender": { "id": "uuid", "name": "Col. Verma" },
  "recipients": [...],
  "created_at": "2026-09-22T18:00:00Z"
}
```

---

## 4. Blockchain Ledger — `/api/blockchain`

### GET `/api/blockchain/events`
Query decryption events. Admin or investigator role required.

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `doc_hash` | string | Filter by document hash |
| `recipient_id` | string | Filter by recipient UUID |
| `watermark_id` | string | Filter by watermark ID |
| `limit` | int | Max results (default 50) |
| `offset` | int | Pagination offset |

**Response `200`:**
```json
[
  {
    "event_id": "evt_hash...",
    "doc_hash": "sha3_256...",
    "doc_cid": "Qm...",
    "recipient_id": "uuid",
    "recipient_email": "sharma@mod.gov.in",
    "watermark_id": "sha3_256...",
    "timestamp": 1727018000,
    "dilithium_signature": "base64...",
    "signature_verified": true
  }
]
```

### GET `/api/blockchain/events/{event_id}`
Get a single event by its ID.

---

## 5. Attribution Engine — `/api/attribution`

### POST `/api/attribution/analyze`
Upload a leaked document for attribution analysis. Investigator role required.

**Request:** `multipart/form-data`
```
file: <leaked PDF binary>
```

**Response `200`:**
```json
{
  "watermark_found": true,
  "watermark_id": "a3f8b2c1d4e5f6a7...",
  "attribution": {
    "recipient_id": "uuid",
    "recipient_email": "sharma@mod.gov.in",
    "recipient_name": "General Sharma",
    "decryption_timestamp": "2026-09-20T14:32:11Z",
    "document": {
      "id": "uuid",
      "title": "Operation XYZ Briefing",
      "doc_hash": "sha3_256..."
    },
    "signature_verified": true,
    "blockchain_event_id": "evt_hash..."
  },
  "evidence_report": {
    "summary": "Document traced to General Sharma who decrypted it on 2026-09-20 at 14:32 UTC",
    "confidence": "CRYPTOGRAPHIC",  // Signature verified on blockchain
    "blockchain_proof": { /* full DecryptionEvent from Fabric */ }
  }
}
```

**Response `200` (no watermark found):**
```json
{
  "watermark_found": false,
  "watermark_id": null,
  "attribution": null,
  "evidence_report": {
    "summary": "No forensic watermark detected in the provided document",
    "confidence": "NONE"
  }
}
```

---

## 6. Error Responses

All errors follow the same structure:
```json
{
  "detail": "Human-readable error message",
  "error_code": "MACHINE_READABLE_CODE"  // optional
}
```

| HTTP Code | When |
|---|---|
| `400 Bad Request` | Invalid input, malformed request |
| `401 Unauthorized` | Missing or invalid JWT token |
| `403 Forbidden` | Valid token but insufficient permissions |
| `404 Not Found` | Resource does not exist |
| `409 Conflict` | Resource already exists (e.g., duplicate event) |
| `413 Payload Too Large` | File exceeds 100MB limit |
| `415 Unsupported Media Type` | Non-PDF file uploaded |
| `422 Unprocessable Entity` | Pydantic validation failed |
| `500 Internal Server Error` | Unexpected server error |

---

## 7. Rate Limits

| Endpoint | Limit |
|---|---|
| `POST /auth/login` | 5 req/min per IP |
| `POST /auth/register` | 3 req/min per IP |
| `POST /docs/upload` | 10 req/min per user |
| `POST /docs/decrypt/*` | 20 req/min per user |
| `POST /attribution/analyze` | 10 req/min per user |
| All other endpoints | 100 req/min per user |
