# Cryptography Guide — SIH26237

> Complete cryptography knowledge for this project — readable by developers and AI agents with no prior PQC background.

---

## 1. Why Post-Quantum Cryptography?

### The Quantum Threat
Classical asymmetric cryptography (RSA, ECDSA, ECDH) relies on mathematical problems that are hard for classical computers:
- RSA → hardness of factoring large integers
- ECDSA → hardness of elliptic curve discrete logarithm

**Shor's Algorithm** (1994) — a quantum algorithm — can solve both problems in polynomial time on a sufficiently powerful quantum computer. When quantum computers become powerful enough, all RSA and ECC keys are instantly breakable.

### NIST's Response
In 2022–2024, NIST standardized the first post-quantum cryptography algorithms:
- **FIPS 203 (ML-KEM)** → based on CRYSTALS-Kyber → for key encapsulation
- **FIPS 204 (ML-DSA)** → based on CRYSTALS-Dilithium → for digital signatures
- **FIPS 205 (SLH-DSA)** → based on SPHINCS+ → hash-based signatures

**This project uses ML-KEM (Kyber-1024) and ML-DSA (Dilithium-3).**

---

## 2. Algorithms Used in This Project

### 2.1 Kyber-1024 (Key Encapsulation Mechanism)

**What it is:** A lattice-based KEM. "Kyber" is the informal name; its NIST standard name is ML-KEM.

**Security level:** Kyber-1024 targets NIST Security Level 5 (equivalent to AES-256).

**Mathematical basis:** Learning With Errors (LWE) over module lattices. Breaking it requires solving hard lattice problems — currently believed to be hard even for quantum computers.

**How KEM works (conceptually):**
```
Alice (recipient) has:   public key (pk) + private key (sk)

Bob (sender) wants to securely share a random secret K with Alice:
  1. Bob calls  Encapsulate(pk) → (ciphertext C, shared_secret K)
  2. Bob sends C to Alice (but keeps K)

Alice:
  3. Alice calls  Decapsulate(sk, C) → shared_secret K

Now both have K without K ever traveling over the network.
```

**In our system:**
```python
import oqs  # liboqs-python

# Key generation (done once per user at registration)
kem = oqs.KeyEncapsulation("Kyber1024")
public_key = kem.generate_keypair()
secret_key = kem.export_secret_key()

# Encapsulation (sender side — wraps AES key)
kem_sender = oqs.KeyEncapsulation("Kyber1024")
ciphertext, shared_secret = kem_sender.encap_secret(public_key)
# shared_secret is a 32-byte random value → use as AES key

# Decapsulation (recipient side — recovers AES key)
kem_recipient = oqs.KeyEncapsulation("Kyber1024", secret_key)
recovered_secret = kem_recipient.decap_secret(ciphertext)
# recovered_secret == shared_secret ✓
```

**Key sizes (Kyber-1024):**
| Parameter | Size |
|---|---|
| Public key | 1568 bytes |
| Secret key | 3168 bytes |
| Ciphertext (capsule) | 1568 bytes |
| Shared secret | 32 bytes |

---

### 2.2 Dilithium-3 (Digital Signature)

**What it is:** A lattice-based digital signature scheme. NIST standard name: ML-DSA.

**Security level:** Dilithium-3 targets NIST Security Level 3 (≈ AES-192).

**Mathematical basis:** Module Learning With Errors (MLWE) and Module Short Integer Solution (MSIS).

**How digital signatures work:**
```
Alice has: public key (vk) + private key (sk)

Alice wants to prove she signed a message M:
  1. Alice: sig = Sign(sk, M)
  2. Alice sends (M, sig)

Anyone can verify:
  3. Verify(vk, M, sig) → True/False
```

**In our system:** Recipients sign decryption event records to prove they personally initiated the decryption.

```python
import oqs

# Key generation (done once per user at registration)
signer = oqs.Signature("Dilithium3")
verify_key = signer.generate_keypair()
sign_key = signer.export_secret_key()

# Signing (recipient signs the decryption record)
message = b'{"docHash":"abc...","watermarkId":"xyz...","ts":1727000000}'
signer_with_key = oqs.Signature("Dilithium3", sign_key)
signature = signer_with_key.sign(message)

# Verification (server or investigator verifies)
verifier = oqs.Signature("Dilithium3")
is_valid = verifier.verify(message, signature, verify_key)  # True
```

**Key sizes (Dilithium-3):**
| Parameter | Size |
|---|---|
| Public key (vk) | 1952 bytes |
| Secret key (sk) | 4000 bytes |
| Signature | ~3293 bytes |

---

### 2.3 AES-256-GCM (Symmetric Encryption)

**What it is:** Advanced Encryption Standard with 256-bit key in Galois/Counter Mode.

**Why symmetric?** Post-quantum KEM is used to exchange a key. The actual document is encrypted with AES — which is fast and quantum-resistant enough (Grover's algorithm halves key security: 256-bit → 128-bit effective, still secure).

**GCM mode provides:**
- Confidentiality (encryption)
- Authenticity (GMAC tag — detects tampering)
- Integrity

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Encryption
key = os.urandom(32)        # 256-bit AES key
nonce = os.urandom(12)      # 96-bit nonce (GCM standard)
aad = b"additional_auth_data"  # optional associated data

aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
# ciphertext includes 16-byte GCM authentication tag appended

# Decryption
plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
# Raises InvalidTag if tampered
```

**IMPORTANT:** Never reuse a (key, nonce) pair. Always generate a fresh nonce with `os.urandom(12)`.

---

### 2.4 SHA3-256 (Watermark ID Generation)

SHA-3 (Keccak) is the latest NIST hash standard (FIPS 202). Unlike SHA-2, it is based on a sponge construction — resistant to length-extension attacks.

**Watermark ID formula:**
```python
import hashlib
import secrets

def generate_watermark_id(
    recipient_id: str,
    doc_cid: str,
    timestamp: int,
) -> str:
    """Generate a unique, deterministic watermark ID for a decryption session."""
    nonce = secrets.token_bytes(32)
    payload = f"{recipient_id}|{doc_cid}|{timestamp}".encode() + nonce
    return hashlib.sha3_256(payload).hexdigest()
```

The nonce ensures even two decryptions by the same recipient of the same doc at the same second produce different watermark IDs.

---

## 3. Hybrid Encryption — The Full Picture

The complete encryption scheme combines all the above:

```
ENCRYPTION (sender side):
────────────────────────
1. Generate random AES-256 key K (32 bytes, os.urandom)
2. Encrypt document D with AES-256-GCM(K) → ciphertext C
3. For each recipient Rᵢ with public key PKᵢ:
   Kyber.Encapsulate(PKᵢ) → (capsuleᵢ, K)
   Store capsuleᵢ in DB against recipientᵢ
4. Store C on IPFS → get CID
5. Discard K from memory

DECRYPTION (recipient side):
────────────────────────────
1. Retrieve capsule for this recipient from DB
2. Recipient provides their Kyber private key SK
   Kyber.Decapsulate(SK, capsule) → K
3. Fetch ciphertext C from IPFS using CID
4. Decrypt: AES-256-GCM(K).decrypt(C) → plaintext D
5. Inject watermark into D → D'
6. Sign event record with Dilithium-3 SK
7. Log to Fabric. Return D' to recipient.
```

---

## 4. liboqs — The PQC Library

**liboqs** (Open Quantum Safe) is an open-source C library with bindings for Python, Go, JavaScript, and others. It implements NIST-standardized PQC algorithms.

### Installation
```bash
pip install liboqs-python==0.10.1
# Note: liboqs-python requires the liboqs C library to be compiled.
# In Docker, use the provided Dockerfile which handles this.
```

### Supported Algorithms (we use)
```python
import oqs

# List all available algorithms
print(oqs.get_enabled_KEM_mechanisms())      # Lists KEMs
print(oqs.get_enabled_sig_mechanisms())      # Lists signature schemes

# Algorithms used in this project:
# KEM:       "Kyber1024"
# Signature: "Dilithium3"
```

### Error Handling
```python
try:
    result = kem.decap_secret(invalid_capsule)
except oqs.MechanismNotEnabledError:
    raise HTTPException(status_code=500, detail="PQC algorithm not available")
except Exception as e:
    raise HTTPException(status_code=400, detail="Decapsulation failed — invalid capsule or key")
```

---

## 5. Key Management Architecture

### What the Server Stores
```
PostgreSQL: public_keys table
┌─────────────────────────────────────────────────────┐
│ user_id | algorithm    | public_key (base64) | type  │
│---------|--------------|---------------------|-------|│
│ uuid-1  | Kyber1024    | AABC...             | KEM   │
│ uuid-1  | Dilithium3   | XYZQ...             | SIG   │
└─────────────────────────────────────────────────────┘
```

### What the User Holds
```
User's browser / local file / hardware token:
  - kyber_private_key.bin   (3168 bytes) — NEVER sent to server
  - dilithium_private_key.bin (4000 bytes) — NEVER sent to server
```

### Key Generation Flow (at registration)
```
Browser (liboqs-js WebAssembly):
  1. Generate Kyber-1024 keypair → (pk_kem, sk_kem)
  2. Generate Dilithium-3 keypair → (pk_sig, sk_sig)
  3. Send pk_kem + pk_sig to server → stored in DB
  4. Download sk_kem + sk_sig → stored by user
  5. sk_kem + sk_sig NEVER leave the browser
```

---

## 6. Security Properties Summary

| Property | Mechanism | Guarantee |
|---|---|---|
| Confidentiality | AES-256-GCM | Only authorized recipients read documents |
| Key Security | Kyber-1024 KEM | AES keys are quantum-resistant |
| Non-repudiation | Dilithium-3 signature | Recipient cannot deny initiating decryption |
| Integrity | AES-GCM auth tag | Ciphertext tampering is detected |
| Authenticity | SHA3-256 watermark ID | Decrypted copy is uniquely fingerprinted |
| Immutability | Hyperledger Fabric | Audit log cannot be altered by anyone |

---

## 7. What NOT to Use (and Why)

| Algorithm | Why Forbidden |
|---|---|
| RSA-2048/4096 | Broken by Shor's algorithm on quantum computers |
| ECDSA (secp256k1, P-256) | Broken by Shor's algorithm |
| ECDH | Broken by Shor's algorithm |
| MD5, SHA-1 | Collision vulnerabilities — never use for security |
| Python `random` module | Not cryptographically secure — use `secrets` |
| ECB mode (AES) | No IV → deterministic → pattern-revealing |
| CBC mode (AES) | Padding oracle attacks — use GCM instead |
