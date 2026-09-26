# SIH-237 — Fresh Low-Level Design (LLD)
## Secure Document Distribution, Forensic Attribution & Tamper-Evident Audit System

**Version:** 2.0  
**Design status:** Implementation baseline  
**Deployment model:** Fully offline / air-gapped  
**Primary backend:** Node.js + Express.js + TypeScript  
**Frontend:** React  
**Authoritative audit ledger:** Hyperledger Fabric  
**Document encryption:** AES-256-GCM  
**PQC key establishment:** ML-KEM  
**PQC signatures:** ML-DSA  

---

## 1. Purpose

This LLD translates the SIH-237 requirements and current HLD into implementation-level components, interfaces, data structures, cryptographic flows, state machines, APIs, failure handling, and deployment boundaries.

The system must:

1. Encrypt a document once.
2. Give authorized recipients controlled decryption access.
3. Generate a unique, invisible forensic watermark for every decryption session.
4. Keep the visible document content visually identical for different recipients.
5. Cryptographically bind the watermark/decryption event to the recipient.
6. Have the recipient's ML-DSA private key sign the canonical decryption event.
7. Commit the signed event to an offline, permissioned Hyperledger Fabric network.
8. Prevent historical provenance records from being modified or deleted.
9. Provide a forensic workflow that extracts a leaked watermark and verifies the corresponding ledger evidence.
10. Operate without cloud KMS, public blockchain, or Internet dependency.

---

# 2. Design Principles

### 2.1 Encrypt once

The source document is encrypted once with a random AES-256-GCM document encryption key (DEK).

Recipient-specific protection is applied to the DEK, not to the complete document.

### 2.2 Post-quantum cryptography

Use:

- ML-KEM for recipient-specific key establishment.
- ML-DSA for recipient-controlled signatures.

Do not replace either with RSA/ECDH/ECDSA.

Do not implement cryptographic primitives from scratch.

Use a vetted implementation behind an application adapter.

### 2.3 Private-key boundary

Recipient private keys stay inside a local secure key-agent boundary.

The application can request:

- decapsulation
- signing

but never receives the recipient's private key bytes.

### 2.4 Fail closed

A forensic document must not be released when any mandatory security step fails.

Required successful sequence:

DECRYPT
→ FINGERPRINT
→ WATERMARK
→ SIGN
→ FABRIC COMMIT
→ VERIFY
→ RELEASE

### 2.5 Prevention + attribution

Secure Viewer/DLP attempts to reduce ordinary digital copying.

Forensic watermarking provides attribution when copies still escape the viewer.

The system must not claim that software can absolutely prevent physical camera capture.

### 2.6 Immutable provenance

The application database stores operational metadata.

Hyperledger Fabric is the authoritative provenance layer.

Historical provenance records are append-only.

---

# 3. Logical Architecture

```text
                    AIR-GAPPED NETWORK
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  ┌──────────────────┐       ┌───────────────────────────┐   │
│  │ React Secure     │ HTTPS │ Node.js / Express API     │   │
│  │ Viewer            ├──────►│                          │   │
│  └──────────────────┘       │ Auth / Policy / Sessions  │   │
│                             │ Documents / Crypto        │   │
│                             │ Watermark / Forensics     │   │
│                             │ Ledger Adapter            │   │
│                             └─────────────┬─────────────┘   │
│                                           │                 │
│              ┌────────────────────────────┼────────────┐    │
│              │                            │            │    │
│              ▼                            ▼            ▼    │
│       ┌──────────────┐          ┌──────────────┐ ┌────────┐ │
│       │ Application  │          │ Watermark /  │ │ Key    │ │
│       │ Database     │          │ Forensics    │ │ Agent  │ │
│       └──────────────┘          └──────────────┘ └───┬────┘ │
│                                                     │      │
│                                                     ▼      │
│                                           ML-KEM / ML-DSA  │
│                                                             │
│                             ┌────────────────────────────┐  │
│                             │ Hyperledger Fabric         │  │
│                             │ Multi-Organization         │  │
│                             │ Permissioned Ledger        │  │
│                             └────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

# 4. Repository Structure

```text
sih-237/
├── apps/
│   ├── api/
│   │   ├── src/
│   │   │   ├── config/
│   │   │   ├── middleware/
│   │   │   ├── modules/
│   │   │   │   ├── auth/
│   │   │   │   ├── users/
│   │   │   │   ├── recipients/
│   │   │   │   ├── devices/
│   │   │   │   ├── documents/
│   │   │   │   ├── encryption/
│   │   │   │   ├── key-envelopes/
│   │   │   │   ├── sessions/
│   │   │   │   ├── watermark/
│   │   │   │   ├── viewer/
│   │   │   │   ├── ledger/
│   │   │   │   └── forensics/
│   │   │   ├── crypto/
│   │   │   │   ├── aes-gcm/
│   │   │   │   ├── ml-kem/
│   │   │   │   ├── ml-dsa/
│   │   │   │   ├── kdf/
│   │   │   │   └── hashing/
│   │   │   ├── services/
│   │   │   ├── repositories/
│   │   │   ├── types/
│   │   │   ├── utils/
│   │   │   └── app.ts
│   │   └── tests/
│   │
│   ├── secure-viewer/
│   │   ├── src/
│   │   └── tests/
│   │
│   └── watermark-service/
│       ├── src/
│       │   ├── embed/
│       │   ├── extract/
│       │   ├── ecc/
│       │   ├── transforms/
│       │   └── evaluation/
│       └── tests/
│
├── packages/
│   ├── shared-types/
│   ├── canonical-events/
│   ├── crypto-contracts/
│   └── validation/
│
├── fabric/
│   ├── organizations/
│   ├── network/
│   ├── chaincode/
│   │   └── provenance/
│   └── scripts/
│
├── infrastructure/
│   ├── docker/
│   ├── compose/
│   ├── offline/
│   └── config/
│
├── docs/
│   ├── architecture.md
│   ├── cryptography.md
│   ├── watermarking.md
│   ├── forensic-verification.md
│   ├── fabric.md
│   ├── threat-model.md
│   └── deployment.md
│
└── README.md
```

---

# 5. Module Design

## 5.1 Authentication Module

Responsibilities:

- user registration
- login
- logout
- session creation
- session revocation
- credential validation
- authentication events

Interfaces:

```ts
interface AuthService {
  register(input: RegisterInput): Promise<User>;
  login(input: LoginInput): Promise<AuthSession>;
  logout(sessionId: string): Promise<void>;
  revokeAll(userId: string): Promise<void>;
}
```

Security:

- password hashing using an approved password hashing scheme
- secure session identifiers
- rate limiting
- account lockout/risk controls as required
- no password logging

---

# 6. Authorization / RBAC

Roles:

```text
ADMIN
DOCUMENT_OWNER
RECIPIENT
INVESTIGATOR
AUDITOR
```

Authorization must be checked at the service layer, not only in routes.

Example:

```ts
authorize({
  userId,
  resource: documentId,
  action: "DECRYPT"
});
```

Policy decision:

```text
Authenticated?
      |
      v
Correct role?
      |
      v
Document access exists?
      |
      v
Session valid?
      |
      v
Device permitted?
      |
      v
Policy allows decryption?
```

---

# 7. Document Lifecycle

```text
UPLOADED
   |
   v
HASHED
   |
   v
ENCRYPTED
   |
   v
KEY_ENVELOPES_CREATED
   |
   v
READY
   |
   v
ACCESS_GRANTED
   |
   v
DECRYPTION_SESSION
   |
   v
FORENSIC_WATERMARKED
   |
   v
SIGNED
   |
   v
LEDGER_COMMITTED
   |
   v
RELEASED
```

Failure states:

```text
WATERMARK_FAILED
SIGNATURE_FAILED
LEDGER_FAILED
VERIFICATION_FAILED
REVOKED
```

No document release from a mandatory failure state.

---

# 8. AES-256-GCM Encryption

## 8.1 Upload

Input:

```text
sourceDocument
```

Process:

```text
random 256-bit DEK
random nonce
AES-256-GCM
```

Associated authenticated data should bind immutable metadata such as:

```text
documentId
documentVersion
algorithmVersion
```

Output:

```ts
EncryptedDocument {
  documentId: string;
  version: number;
  ciphertext: Buffer;
  nonce: Buffer;
  authTag: Buffer;
  documentHash: string;
  encryptionAlgorithm: "AES-256-GCM";
}
```

The plaintext document should not be retained unnecessarily.

---

# 9. Document Hash

Calculate a cryptographic hash of the canonical source document:

```text
documentHash = SHA-256(canonicalDocumentBytes)
```

The hash is used to bind:

- document metadata
- key envelope
- decryption event
- watermark commitment
- forensic investigation

The hash is not a substitute for encryption.

---

# 10. ML-KEM Key Envelope

Each authorized recipient has an ML-KEM public key.

For recipient R:

```text
Document DEK
     |
     | protected using recipient-specific key material
     v
Recipient Key Envelope
```

Detailed flow:

```text
Recipient ML-KEM public key
             |
             v
       ML-KEM Encaps
             |
             v
       Shared Secret
             |
             v
      KDF / HKDF
             |
             v
      Wrapping Key
             |
             v
  Authenticated DEK wrapping
             |
             v
      Key Envelope
```

The key envelope contains metadata such as:

```ts
interface KeyEnvelope {
  id: string;
  documentId: string;
  recipientId: string;
  kemAlgorithm: string;
  kemCiphertext: Buffer;
  wrappedDek: Buffer;
  wrappingNonce: Buffer;
  wrappingTag: Buffer;
  keyVersion: string;
}
```

Never store the recipient private ML-KEM key in the database.

---

# 11. Local Key Agent

The key agent is the security boundary for recipient private keys.

```text
Node Backend
     |
     | authenticated local IPC / protected local interface
     v
Key Agent
     |
     +---- ML-KEM Decapsulation
     |
     +---- ML-DSA Signing
```

Interfaces:

```ts
interface KeyAgent {
  decapsulate(
    recipientKeyId: string,
    kemCiphertext: Buffer
  ): Promise<Buffer>;

  sign(
    signingKeyId: string,
    digest: Buffer
  ): Promise<Buffer>;
}
```

The backend receives only:

- shared secret
- signature

It never receives private key material.

For production hardware, the same interface can later map to an HSM or equivalent secure hardware.

---

# 12. Decryption Session

Create a session before decryption.

```ts
interface DecryptionSession {
  sessionId: string;
  documentId: string;
  recipientId: string;
  deviceId: string;
  startedAt: Date;
  expiresAt: Date;
  status:
    | "CREATED"
    | "AUTHORIZED"
    | "DECRYPTED"
    | "WATERMARKED"
    | "SIGNED"
    | "COMMITTED"
    | "RELEASED"
    | "FAILED"
    | "REVOKED";
  nonce: string;
}
```

The session must have sufficient entropy to prevent collisions.

---

# 13. Decryption Sequence

```text
Recipient
   |
   v
Authenticate
   |
   v
Create Session
   |
   v
Authorization
   |
   v
Retrieve Key Envelope
   |
   v
Key Agent
   |
   v
ML-KEM Decapsulation
   |
   v
Shared Secret
   |
   v
KDF
   |
   v
Recover DEK
   |
   v
AES-256-GCM Decrypt
   |
   v
Verify document hash
```

Do not release the document yet.

---

# 14. Forensic Fingerprint

Generate a per-session opaque fingerprint.

Conceptual input:

```text
domainSeparator
documentId
documentHash
recipientId
sessionId
randomNonce
watermarkVersion
```

Use a KDF/HMAC-style construction based on approved cryptographic primitives.

Example conceptual output:

```text
fingerprintPayload
```

Then:

```text
watermarkCommitment =
SHA-256(fingerprintPayload)
```

Do not embed direct PII.

---

# 15. Watermark Payload

Recommended structure:

```ts
interface WatermarkPayload {
  version: number;
  watermarkId: string;
  documentBinding: string;
  sessionBinding: string;
  payloadDigest: string;
  eccData: Buffer;
}
```

The payload should be encoded into a compact binary representation before watermark embedding.

Do not place JSON directly into an image/document watermark.

---

# 16. Watermark Embedding

Architecture:

```text
Decrypted Document
       |
       v
Render / Normalize
       |
       v
Fingerprint Payload
       |
       v
ECC Encoding
       |
       v
Watermark Encoder
       |
       v
Forensic Document
```

The visible document content should remain visually identical.

The watermark must be evaluated using objective image-quality measurements.

Potential metrics:

- PSNR
- SSIM
- perceptual difference
- extraction accuracy

---

# 17. Camera-Resilient Watermarking

The system should evaluate the watermark against transformations such as:

```text
resize
crop
rotation
blur
JPEG compression
perspective distortion
lighting variation
color shift
noise
screen capture
camera capture
```

Testing pipeline:

```text
Original Watermarked Render
        |
        v
Transformation Simulator
        |
        v
Synthetic Camera Capture
        |
        v
Watermark Decoder
        |
        v
Recovered Payload
        |
        v
ECC Correction
        |
        v
Commitment Verification
```

A neural watermarking model may be isolated in the watermark service if required by the final implementation.

Do not make unsupported claims about robustness until measured.

---

# 18. Secure Viewer

The viewer receives only an authorized session-bound representation.

Avoid:

```text
GET /document.pdf
```

for unrestricted raw plaintext download.

Preferred flow:

```text
Viewer Session
     |
     v
Authorization
     |
     v
Page/tile request
     |
     v
Controlled rendering
     |
     v
Viewer
```

Controls:

- no ordinary download endpoint
- copy restriction
- print restriction where technically enforceable
- export restriction
- session expiry
- reauthentication
- device/session binding
- revocation checks

Browser controls are deterrence, not absolute protection.

---

# 19. Canonical Decryption Event

Canonical event:

```ts
interface DecryptionEvent {
  eventVersion: string;
  eventId: string;
  eventType: "DOCUMENT_DECRYPTION";

  documentId: string;
  documentHash: string;

  recipientId: string;
  sessionId: string;
  deviceId: string;

  watermarkId: string;
  watermarkCommitment: string;

  signingKeyId: string;
  timestamp: string;
}
```

Canonical serialization must:

- define field order
- define encoding
- define null handling
- define string normalization
- define timestamp format

Never sign arbitrary JavaScript object serialization.

---

# 20. Event Signing

```text
Canonical Event
      |
      v
SHA-256
      |
      v
Event Digest
      |
      v
Key Agent
      |
      v
ML-DSA Sign
      |
      v
Signature
```

Signed event:

```ts
interface SignedDecryptionEvent {
  event: DecryptionEvent;
  eventDigest: string;
  signature: string;
}
```

The signature must bind the recipient, document, session, watermark, and timestamp.

---

# 21. Hyperledger Fabric Provenance

Fabric is the authoritative audit/provenance layer.

Conceptual network:

```text
Organization A
    |
    +-- Peer
    |
Organization B
    |
    +-- Peer
    |
Organization C
    |
    +-- Peer
    |
    v
Ordering Service
    |
    v
Channel
    |
    v
Provenance Chaincode
```

Use endorsement policies requiring multiple organizations where the deployment model permits.

---

# 22. Provenance Chaincode

Records should be append-only.

Example:

```ts
interface LedgerRecord {
  eventId: string;
  eventDigest: string;
  documentId: string;
  documentHash: string;
  recipientId: string;
  sessionId: string;
  watermarkId: string;
  watermarkCommitment: string;
  signingKeyId: string;
  signature: string;
  timestamp: string;
}
```

Operations:

```text
CreateEvent
GetEvent
FindByWatermark
FindByDocument
VerifyEvent
```

Do NOT expose:

```text
UpdateEvent
DeleteEvent
```

If an event must be corrected or revoked, append a new event referencing the earlier event.

---

# 23. Ledger Commit Sequence

```text
Signed Event
     |
     v
Ledger Adapter
     |
     v
Fabric Proposal
     |
     v
Endorsement
     |
     v
Ordering
     |
     v
Commit
     |
     v
Commit Verification
```

The backend must verify successful commitment before document release.

Store the Fabric transaction ID as operational metadata and inside the forensic evidence chain where appropriate.

---

# 24. Fail-Closed Release

Mandatory gate:

```text
DECRYPTION SUCCESS
       AND
DOCUMENT HASH VALID
       AND
WATERMARK SUCCESS
       AND
ML-DSA SIGNATURE VALID
       AND
FABRIC COMMIT SUCCESS
       AND
COMMIT VERIFICATION SUCCESS
       |
       v
RELEASE DOCUMENT
```

Otherwise:

```text
DENY RELEASE
```

Never silently continue after a security-critical failure.

---

# 25. Forensic Investigation

Input:

```text
Leaked PDF / Image / Photograph
```

Pipeline:

```text
Input
 |
 v
Normalize
 |
 v
Detect watermark
 |
 v
Extract payload
 |
 v
ECC decode
 |
 v
Recover watermarkId
 |
 v
Calculate/validate commitment
 |
 v
Query Fabric
 |
 v
Retrieve signed event
 |
 v
Verify ML-DSA signature
 |
 v
Verify document binding
 |
 v
Verify watermark commitment
 |
 v
Generate report
```

---

# 26. Forensic Verification Result

```ts
interface ForensicVerificationResult {
  status: "VERIFIED" | "NOT_FOUND" | "INVALID" | "INCONCLUSIVE";

  watermarkId?: string;
  recipientId?: string;
  documentId?: string;
  sessionId?: string;

  eventId?: string;
  ledgerTransactionId?: string;

  signatureValid: boolean;
  documentHashValid: boolean;
  watermarkCommitmentValid: boolean;

  recoveryConfidence?: number;

  evidence: {
    extractedAt: string;
    extractorVersion: string;
    watermarkAlgorithmVersion: string;
  };
}
```

Use `INCONCLUSIVE` when extraction confidence is insufficient.

Do not force a false attribution.

---

# 27. Database Schema

## User

```text
id
username
email
passwordHash
role
status
createdAt
updatedAt
```

## Recipient

```text
id
userId
mlKemKeyId
mlDsaKeyId
keyStatus
createdAt
updatedAt
```

## Device

```text
id
recipientId
deviceFingerprint
status
lastSeenAt
createdAt
```

## Document

```text
id
ownerId
name
version
documentHash
encryptedStorageRef
encryptionAlgorithm
status
createdAt
```

## KeyEnvelope

```text
id
documentId
recipientId
kemAlgorithm
kemCiphertext
wrappedDek
wrappingNonce
wrappingTag
keyVersion
createdAt
```

## AccessPolicy

```text
id
documentId
recipientId
permissions
validFrom
validUntil
status
```

## DecryptionSession

```text
id
documentId
recipientId
deviceId
status
startedAt
expiresAt
nonce
```

## WatermarkMetadata

```text
id
watermarkId
documentId
sessionId
recipientId
watermarkCommitment
algorithmVersion
createdAt
```

## DecryptionEventMetadata

```text
id
eventId
documentId
recipientId
sessionId
watermarkId
ledgerTransactionId
status
createdAt
```

The database is operational storage, not the immutable evidence source.

---

# 28. API Contracts

## Upload

```http
POST /api/documents
```

Request:

```text
multipart/form-data
```

Response:

```json
{
  "documentId": "...",
  "documentHash": "...",
  "status": "READY"
}
```

---

## Grant Access

```http
POST /api/documents/:documentId/recipients
```

```json
{
  "recipientId": "..."
}
```

Backend:

```text
authorize
→ obtain recipient public ML-KEM key
→ create key envelope
→ persist metadata
```

---

## Start Decryption Session

```http
POST /api/documents/:documentId/decryption-sessions
```

Response:

```json
{
  "sessionId": "...",
  "expiresAt": "..."
}
```

---

## Prepare Forensic Document

```http
POST /api/decryption-sessions/:sessionId/prepare
```

Pipeline:

```text
authorize
→ recover DEK
→ decrypt
→ fingerprint
→ watermark
→ canonical event
→ ML-DSA sign
→ Fabric commit
→ verify
```

---

## Viewer Page

```http
GET /api/viewer/sessions/:sessionId/pages/:pageNumber
```

Must validate:

- authentication
- session
- document access
- session expiration
- device binding
- revocation

---

## Watermark Extraction

```http
POST /api/forensics/extract
```

Input:

```text
leaked file
```

Output:

```json
{
  "watermarkId": "...",
  "confidence": 0.97
}
```

---

## Forensic Verification

```http
POST /api/forensics/verify
```

Input:

```json
{
  "watermarkId": "...",
  "documentHash": "..."
}
```

Output:

```json
{
  "status": "VERIFIED",
  "recipientId": "...",
  "sessionId": "...",
  "eventId": "...",
  "ledgerTransactionId": "...",
  "signatureValid": true,
  "watermarkCommitmentValid": true
}
```

---

# 29. Error Handling

Define typed errors:

```text
AuthenticationError
AuthorizationError
DocumentNotFoundError
SessionExpiredError
KeyEnvelopeError
KEMDecapsulationError
DecryptionError
WatermarkGenerationError
WatermarkExtractionError
SignatureError
LedgerCommitError
LedgerVerificationError
ForensicVerificationError
```

Map errors to safe API responses.

Never return:

- private keys
- cryptographic secrets
- internal stack traces
- plaintext documents
- sensitive database details

---

# 30. Audit Logging

Application logs may record:

```text
eventId
userId
documentId
sessionId
operation
result
timestamp
requestId
```

Do not log:

```text
private keys
DEKs
ML-KEM private key
ML-DSA private key
passwords
plaintext documents
raw watermark secrets
```

The immutable provenance record belongs in Fabric.

---

# 31. Security Boundaries

```text
┌──────────────────────────────────────┐
│ Frontend / Viewer                    │
│ Untrusted execution environment     │
└──────────────────┬───────────────────┘
                   │
                   v
┌──────────────────────────────────────┐
│ Backend                              │
│ Authentication / Authorization       │
│ Business Logic                       │
└──────────┬───────────────┬───────────┘
           │               │
           v               v
┌─────────────────┐   ┌────────────────┐
│ Crypto Adapter  │   │ Watermark      │
│                 │   │ Service        │
└────────┬────────┘   └────────────────┘
         │
         v
┌──────────────────────────────────────┐
│ Secure Key Agent                     │
│ PRIVATE KEY BOUNDARY                 │
└──────────────────────────────────────┘
```

---

# 32. Threat / Control Matrix

| Threat | Control |
|---|---|
| Unauthorized document access | Authentication + authorization |
| Credential theft | Session controls + rate limiting |
| Unauthorized decryption | Access policy + key envelope |
| Document tampering | AES-GCM authentication + hash |
| Forged decryption event | ML-DSA signature |
| Single-admin audit manipulation | Multi-org Fabric endorsement |
| Ledger deletion | Append-only provenance |
| Digital download | Secure viewer |
| Screenshot | Viewer controls + forensic watermark |
| Camera capture | Camera-resilient watermark |
| Watermark corruption | ECC + redundant payload |
| Event tampering | Signature verification |
| Database modification | Fabric as authoritative provenance |
| Private-key exposure | Local key agent |
| Network compromise | Air-gapped deployment |

---

# 33. Testing Architecture

## Unit Tests

Test independently:

- AES-GCM
- SHA-256
- KDF
- ML-KEM adapter
- ML-DSA adapter
- canonical serializer
- fingerprint generation
- watermark encoder
- watermark decoder
- chaincode logic

## Integration Tests

Test:

```text
Backend
+
Database
+
Key Agent
+
Watermark Service
+
Fabric
```

## End-to-End Test

Create:

```text
Recipient A
Recipient B
Recipient C
```

All access the same encrypted document.

Expected:

```text
Same visible document
Different watermark A
Different watermark B
Different watermark C
```

Then leak Recipient B's copy.

Expected:

```text
Watermark B
     ↓
Recipient B
     ↓
Session B
     ↓
Signed Event B
     ↓
Fabric Record B
```

---

# 34. Watermark Robustness Test Matrix

| Transformation | Expected Test |
|---|---|
| JPEG compression | extraction accuracy |
| Resize | extraction accuracy |
| Crop | extraction accuracy |
| Rotation | extraction accuracy |
| Blur | extraction accuracy |
| Perspective | extraction accuracy |
| Brightness | extraction accuracy |
| Contrast | extraction accuracy |
| Color shift | extraction accuracy |
| Screenshot | extraction accuracy |
| Camera photograph | extraction accuracy |
| Noise | extraction accuracy |

Record:

```text
attack/transformation
payload recovery rate
bit error rate
ECC correction rate
false-positive rate
false-negative rate
confidence
```

---

# 35. Performance Considerations

Measure:

- encryption time
- ML-KEM operation latency
- watermark generation latency
- ML-DSA signing latency
- Fabric commit latency
- viewer page rendering latency
- watermark extraction latency

Do not optimize prematurely.

Security-critical correctness comes first.

---

# 36. Offline Deployment

Recommended services:

```text
reverse-proxy
api
frontend
database
key-agent
watermark-service
fabric-ca
fabric-peer-org1
fabric-peer-org2
fabric-orderer
fabric-chaincode
```

All container images and dependencies must be available inside the air-gapped environment.

No runtime Internet dependency.

---

# 37. Configuration

Never hardcode secrets.

Example:

```text
APP_ENV
DATABASE_URL
SESSION_SECRET
KEY_AGENT_ENDPOINT
FABRIC_NETWORK_CONFIG
FABRIC_CHANNEL
FABRIC_CHAINCODE
WATERMARK_SERVICE_ENDPOINT
LOG_LEVEL
```

Secrets should be supplied through the approved local secret mechanism.

---

# 38. Versioning

Version:

- encryption metadata
- watermark algorithm
- watermark payload
- canonical event schema
- chaincode schema
- key versions
- forensic extractor

Example:

```text
cryptoVersion: 1
watermarkVersion: 1
eventVersion: 1
keyVersion: 1
extractorVersion: 1
```

This is important because forensic verification may occur years after a document was distributed.

---

# 39. Key Lifecycle

States:

```text
GENERATED
ACTIVE
SUSPENDED
REVOKED
EXPIRED
DESTROYED
```

Never silently reuse revoked key identifiers.

When a signing key is compromised:

1. mark key revoked
2. record revocation event
3. prevent new signing
4. preserve historical signed events
5. flag affected evidence during investigation

Historical signatures must not be rewritten.

---

# 40. Critical End-to-End Sequence

```text
                    DOCUMENT OWNER

                        |
                        v
                 Upload Document
                        |
                        v
                  SHA-256 Hash
                        |
                        v
                 Random AES DEK
                        |
                        v
                 AES-256-GCM
                        |
                        v
              Encrypted Document
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
      Recipient A   Recipient B   Recipient C
      ML-KEM PK     ML-KEM PK     ML-KEM PK
          |             |             |
          v             v             v
      Key Envelope  Key Envelope  Key Envelope


                  RECIPIENT B

                        |
                        v
                  Authenticate
                        |
                        v
                 Create Session
                        |
                        v
                   Authorize
                        |
                        v
                 ML-KEM Decaps
                        |
                        v
                  Shared Secret
                        |
                        v
                      KDF
                        |
                        v
                  Recover DEK
                        |
                        v
                 AES-GCM Decrypt
                        |
                        v
                Document Integrity
                        |
                        v
              Generate Fingerprint
                        |
                        v
                Invisible Watermark
                        |
                        v
                Canonical Event
                        |
                        v
                  SHA-256 Digest
                        |
                        v
               ML-DSA Signature
                        |
                        v
             Hyperledger Fabric
                        |
                        v
               Multi-Org Endorse
                        |
                        v
                     Commit
                        |
                        v
                 Verify Commit
                        |
                        v
                 Secure Viewer


                     LEAK

                        |
                        v
                Leaked Document
                        |
                        v
               Watermark Extractor
                        |
                        v
                    ECC Decode
                        |
                        v
                  Watermark ID
                        |
                        v
               Fabric Lookup
                        |
                        v
             Signed Event Retrieved
                        |
                        v
              ML-DSA Verification
                        |
                        v
             Document Hash Binding
                        |
                        v
           Watermark Commitment Check
                        |
                        v
              Forensic Report
```

---

# 41. Implementation Order

Implement in this exact dependency order:

### Stage 1
Repository + configuration + database + API foundation.

### Stage 2
Authentication + authorization + RBAC + sessions.

### Stage 3
Document upload + hashing + AES-256-GCM.

### Stage 4
ML-KEM adapter + key envelopes + local key agent.

### Stage 5
Decryption session state machine.

### Stage 6
Fingerprint generation.

### Stage 7
Watermark embedding/extraction + ECC.

### Stage 8
ML-DSA signing + canonical events.

### Stage 9
Hyperledger Fabric network + chaincode + endorsement.

### Stage 10
Secure viewer.

### Stage 11
Forensic investigation.

### Stage 12
End-to-end integration.

### Stage 13
Security testing + robustness testing.

### Stage 14
Offline deployment packaging.

---

# 42. Definition of Done

The implementation is complete only when:

- [ ] Document is encrypted exactly once.
- [ ] AES-256-GCM encryption works.
- [ ] Recipient-specific ML-KEM key protection works.
- [ ] ML-KEM private keys never leave the key-agent boundary.
- [ ] ML-DSA signing works.
- [ ] ML-DSA private keys never enter backend storage.
- [ ] Every decryption session gets a unique fingerprint.
- [ ] Watermark is invisible during normal viewing.
- [ ] Alice/Bob/Charlie copies are visually identical.
- [ ] Alice/Bob/Charlie watermarks are different.
- [ ] Watermark is bound to document/session/recipient evidence.
- [ ] Secure viewer prevents ordinary raw document download.
- [ ] Fabric records are append-only.
- [ ] Multi-organization endorsement is configured.
- [ ] Historical ledger records cannot be updated/deleted.
- [ ] Watermark can be extracted from supported leak transformations.
- [ ] Fabric lookup returns the matching event.
- [ ] ML-DSA signature verifies.
- [ ] Document binding verifies.
- [ ] Watermark commitment verifies.
- [ ] Failed watermarking prevents release.
- [ ] Failed signature prevents release.
- [ ] Failed ledger commit prevents release.
- [ ] Complete system works without Internet access.
- [ ] No cloud KMS is required.
- [ ] No public blockchain is required.
- [ ] Security limitations are documented.
- [ ] Unit, integration, security, and end-to-end tests pass.
