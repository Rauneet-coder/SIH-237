# Security Model — SIH26237

> Threat model, attack surfaces, security guarantees, and design decisions explained from first principles.

---

## 1. Security Goals (What We're Protecting)

| Goal | Description |
|---|---|
| **Confidentiality** | Only authorized recipients can read document content |
| **Non-Repudiation** | A recipient cannot deny having decrypted a document |
| **Integrity** | Documents cannot be tampered with in transit or storage |
| **Immutability** | Decryption audit logs cannot be altered by anyone |
| **Attribution** | If a document leaks, the source can be cryptographically identified |
| **Forward Secrecy** | Quantum computers in the future cannot break past encryptions |

---

## 2. Threat Model — Who Are the Adversaries?

### Adversary 1: Malicious Recipient (Primary Threat)
**Profile:** An authorized user who decrypts a document and intentionally leaks it.

**Capabilities:**
- Has a valid account and authorized access
- Has their own private key
- Can save and share the document they receive

**Our Defense:**
- Invisible watermark embeds their identity in the document
- Blockchain immutably records their decryption event
- Watermark extraction + blockchain query → cryptographic attribution

---

### Adversary 2: External Attacker (Network Interception)
**Profile:** An attacker who intercepts network traffic or gains unauthorized access.

**Capabilities:**
- Can observe network traffic
- May attempt to intercept document transfers
- May brute-force authentication

**Our Defense:**
- All APIs served over HTTPS/TLS
- Documents stored encrypted on IPFS (AES-256-GCM)
- Post-quantum KEM — quantum computers cannot break Kyber-1024
- JWT authentication on every endpoint
- Rate limiting on auth endpoints

---

### Adversary 3: Compromised System Administrator
**Profile:** An admin who has server access but wants to cover up a leak or erase audit logs.

**Capabilities:**
- Database access (PostgreSQL)
- IPFS node access
- Application server access

**Our Defense:**
- Admin has **no access to the blockchain** — Fabric is a separate infrastructure
- Chaincode has **no delete/update function** — admin cannot call what doesn't exist
- Even with DB access, they cannot modify the Fabric ledger without compromising all peers
- Private keys are never stored on server — admin cannot retroactively decrypt

---

### Adversary 4: Quantum Computer (Future Threat)
**Profile:** A nation-state adversary with a cryptographically-relevant quantum computer.

**Capabilities:**
- Can run Shor's algorithm to break RSA/ECDSA
- Can run Grover's algorithm (halves symmetric key security)

**Our Defense:**
- **Kyber-1024** (NIST Level 5) — quantum-resistant KEM
- **Dilithium-3** (NIST Level 3) — quantum-resistant signatures
- **AES-256** — Grover's reduces to 128-bit effective security — still secure

---

## 3. Trust Hierarchy

```
FULLY TRUSTED:
  - Hyperledger Fabric orderer + peers (separate from app server)
  - Fabric chaincode (code-auditable, no delete functions)

PARTIALLY TRUSTED:
  - Backend application server (can be compromised, but damage is limited)
  - IPFS node (stores only encrypted data — plaintext never present)
  - PostgreSQL (stores only public keys and metadata, no private keys)

UNTRUSTED:
  - Recipient's client (browser/device)
  - Network (all traffic encrypted)
  - Application admin (no blockchain access)

NEVER TRUSTED (private keys):
  - Server NEVER holds private keys — ever
  - No exception, no workaround, no "temporary" storage
```

---

## 4. Attack Surface Analysis

### 4.1 Authentication Endpoint (`/api/auth/login`)
**Risk:** Brute force, credential stuffing  
**Mitigations:**
- bcrypt password hashing (cost factor 12)
- Rate limiting: max 5 attempts per minute per IP
- Account lockout after 10 failed attempts

### 4.2 Document Upload (`/api/docs/upload`)
**Risk:** Malicious file upload (polyglot files, zip bombs, macro-embedded PDFs)  
**Mitigations:**
- File type validation: check magic bytes (not just extension)
- Size limit: 100MB hard cap
- Content-type validation
- PDF parsing in sandboxed context

### 4.3 Decryption Endpoint (`/api/docs/decrypt/{id}`)
**Risk:** Unauthorized access, IDOR (Insecure Direct Object Reference)  
**Mitigations:**
- JWT authentication required
- Authorization check: recipientID must be in document's recipient list
- Watermark always injected before delivery — raw bytes never returned
- Decryption event always logged (cannot decrypt without logging)

### 4.4 Attribution Upload (`/api/attribution/analyze`)
**Risk:** Uploading arbitrary files, DoS via large files  
**Mitigations:**
- Auth required (investigator role)
- Same file validation as document upload
- Rate limited

### 4.5 Blockchain Gateway
**Risk:** Replay attacks, unauthorized chaincode invocation  
**Mitigations:**
- Fabric MSP certificate authentication
- TLS between backend and peer
- Timestamp in every transaction (replay window < 15 seconds in Fabric)

---

## 5. Data Classification

| Data | Classification | Storage | Who Can Access |
|---|---|---|---|
| Private keys (Kyber, Dilithium) | TOP SECRET | User device only | User only |
| AES document key | SECRET | RAM only during decryption | Backend (ephemerally) |
| Encrypted document | SENSITIVE | IPFS (private) | Backend with CID |
| Decryption event log | SENSITIVE | Hyperledger Fabric | Backend + Fabric admins |
| Watermark ID | SENSITIVE | Fabric + embedded in PDF | Backend |
| Public keys | INTERNAL | PostgreSQL | Backend API |
| JWT tokens | INTERNAL | httpOnly cookies | Browser |
| User emails/metadata | INTERNAL | PostgreSQL | Backend |

---

## 6. Cryptographic Security Properties

### Encryption Security
```
AES-256-GCM provides:
  ✅ Confidentiality     (256-bit key → 128-bit post-quantum security)
  ✅ Authenticity        (GHASH MAC — detects ciphertext tampering)
  ✅ Integrity           (combined with authenticity)

Kyber-1024 provides:
  ✅ IND-CCA2 security   (chosen ciphertext attack resistant)
  ✅ Post-quantum secure  (NIST Level 5)
  ✅ Forward secrecy      (each doc uses fresh AES key)
```

### Signature Security
```
Dilithium-3 provides:
  ✅ EUF-CMA security    (existential unforgeability under chosen message attack)
  ✅ Post-quantum secure  (NIST Level 3)
  ✅ Non-repudiation      (only key holder can produce valid signature)
```

---

## 7. What the System Does NOT Guarantee

Be explicit with evaluators about limitations:

| Limitation | Explanation |
|---|---|
| **Screen capture** | We cannot watermark what someone photographs with another device |
| **Memory scraping** | An attacker with OS-level access could read decrypted bytes from RAM |
| **Collusion** | Two recipients sharing watermarked copies could average them (advanced attack) |
| **Print-scan** | Our text watermark doesn't survive printing + scanning (Phase 2 mitigation: DCT steganography) |
| **Key theft** | If a recipient's private key is stolen, attribution still points to them (they're responsible for key custody) |

---

## 8. Security Checklist (Per Feature)

Before marking any feature complete:
- [ ] All inputs validated (type, size, format, encoding)
- [ ] Authentication required (JWT on endpoint)
- [ ] Authorization enforced (user can only act on their own resources)
- [ ] No sensitive data in logs (no keys, no raw doc content)
- [ ] No raw decrypted bytes returned without watermarking
- [ ] Error messages are generic (don't leak internal details)
- [ ] SQL injection impossible (SQLAlchemy ORM only, no raw SQL)
- [ ] Dependencies checked for known CVEs

---

## 9. Incident Response (If System is Compromised)

### If Backend Server is Compromised
1. Rotate all JWT secrets immediately
2. Force all users to re-login
3. Blockchain audit log is INTACT (Fabric is separate — attacker can't touch it)
4. Encrypted documents on IPFS are still encrypted (attacker has no private keys)
5. Damage: metadata in PostgreSQL may be exposed

### If a Recipient's Private Key is Stolen
1. Attacker can decrypt documents intended for that recipient
2. Blockchain still shows the recipient's account decrypted them
3. Key revocation: admin marks public key as revoked in DB
4. Rotate: recipient generates new keypair, sender re-encrypts for new key

### If the IPFS Node is Compromised
1. Attacker has access to encrypted ciphertexts
2. Without AES keys (which require private key decapsulation), ciphertexts are useless
3. AES-256-GCM — no plaintext is recoverable without the key
