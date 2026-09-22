# Software Requirements Specification (SRS)
## SIH26237 — Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution

**Version:** 1.0  
**Date:** September 2026  
**Organization:** Ministry of Defence  
**Theme:** Blockchain & Cybersecurity  
**PS ID:** SIH26237  
**Hackathon:** Smart India Hackathon (SIH) 2026  

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Overall Description](#2-overall-description)
3. [Stakeholders](#3-stakeholders)
4. [Functional Requirements](#4-functional-requirements)
5. [Non-Functional Requirements](#5-non-functional-requirements)
6. [System Architecture Requirements](#6-system-architecture-requirements)
7. [Cryptographic Requirements](#7-cryptographic-requirements)
8. [Blockchain Requirements](#8-blockchain-requirements)
9. [Watermarking Requirements](#9-watermarking-requirements)
10. [External Interface Requirements](#10-external-interface-requirements)
11. [Security Requirements](#11-security-requirements)
12. [Technology Stack](#12-technology-stack)
13. [Constraints & Assumptions](#13-constraints--assumptions)
14. [Glossary](#14-glossary)

---

## 1. Introduction

### 1.1 Purpose
This Software Requirements Specification (SRS) document defines the complete functional and non-functional requirements for the **Cryptographic Attribution and Immutable Decryption Provenance System** developed for SIH26237. The system ensures that every decryption event for a sensitive encrypted document is immutably logged on a private blockchain, and each decrypted copy carries a unique forensic watermark enabling cryptographic attribution in the event of a data leak.

### 1.2 Scope
The system covers:
- Secure multi-recipient encrypted document distribution
- Post-quantum cryptographic key management
- Invisible forensic watermark injection at decryption time
- Immutable, tamper-evident decryption logging on a private Hyperledger Fabric blockchain
- A cryptographic attribution engine to identify the source of leaked documents

### 1.3 Problem Statement
Sensitive documents distributed using a "broadcast-encrypt, individually-decrypt" model provide no reliable mechanism to identify the source of a data leak when multiple authorized recipients exist. This system solves that by:
- Making every decryption event **cryptographically signed and immutably logged**
- Embedding a **unique, invisible forensic watermark** at the moment of decryption
- Enabling **verifiable attribution** of any leaked copy back to the specific recipient who decrypted it

### 1.4 Definitions
See [Section 14 — Glossary](#14-glossary).

---

## 2. Overall Description

### 2.1 Product Perspective
This is a standalone, self-hosted, air-gap-capable software system. It does not depend on any public cloud service or public blockchain network. All components run within a private, secured network.

### 2.2 Product Functions (Summary)
| # | Function |
|---|---|
| F-01 | User registration with post-quantum keypair generation |
| F-02 | Encrypted document upload and storage (IPFS) |
| F-03 | Multi-recipient document distribution via Kyber KEM |
| F-04 | Authorized decryption with watermark injection |
| F-05 | Immutable decryption event logging on Hyperledger Fabric |
| F-06 | Forensic watermark extraction from leaked documents |
| F-07 | Blockchain-verified attribution report generation |
| F-08 | Administrative dashboards for senders, recipients, and investigators |

### 2.3 User Classes
| User Class | Description |
|---|---|
| **Sender** | Uploads and distributes encrypted documents to recipients |
| **Recipient** | Authorized user who decrypts and accesses documents |
| **Investigator** | Uploads leaked documents to determine who leaked them |
| **System Admin** | Manages users, keys, and infrastructure (no blockchain edit access) |

### 2.4 Operating Environment
- Deployment: Docker containers on private servers / air-gapped intranet
- OS: Linux (Ubuntu 22.04 LTS recommended)
- Network: Private LAN / VPN (no public internet required)

---

## 3. Stakeholders

| Stakeholder | Role | Interest |
|---|---|---|
| Ministry of Defence | Problem Owner | Prevent classified document leaks |
| System Administrator | Operator | Manage infrastructure and users |
| Document Sender | Primary User | Distribute classified documents securely |
| Document Recipient | Primary User | Access documents in their authorized scope |
| Security Investigator | Secondary User | Identify the source of leaked documents |
| Auditor | Observer | Review immutable audit logs on blockchain |

---

## 4. Functional Requirements

### 4.1 User Authentication & Key Management

| Req ID | Requirement | Priority |
|---|---|---|
| FR-01 | The system SHALL allow new users to register with a username, email, and role | HIGH |
| FR-02 | The system SHALL generate a Kyber-1024 keypair (encryption) for each user on registration | HIGH |
| FR-03 | The system SHALL generate a Dilithium-3 keypair (signing) for each user on registration | HIGH |
| FR-04 | Private keys SHALL be delivered to the user and NEVER stored on the server | HIGH |
| FR-05 | The system SHALL store only public keys in the database | HIGH |
| FR-06 | The system SHALL authenticate users using JWT access tokens | HIGH |
| FR-07 | The system SHALL support token expiry and refresh | MEDIUM |

### 4.2 Document Upload & Encryption

| Req ID | Requirement | Priority |
|---|---|---|
| FR-08 | The system SHALL accept PDF documents for upload | HIGH |
| FR-09 | The system SHALL encrypt each document using AES-256-GCM with a randomly generated key | HIGH |
| FR-10 | The system SHALL wrap the AES key for each recipient using Kyber-1024 KEM encapsulation | HIGH |
| FR-11 | The system SHALL store the encrypted document on a private IPFS node | HIGH |
| FR-12 | The system SHALL return a Content Identifier (CID) for each uploaded document | HIGH |
| FR-13 | The system SHALL store document metadata (CID, sender, recipients, timestamp) in the database | HIGH |

### 4.3 Document Decryption & Watermark Injection

| Req ID | Requirement | Priority |
|---|---|---|
| FR-14 | The system SHALL allow only authorized recipients to request decryption | HIGH |
| FR-15 | The system SHALL verify recipient identity before initiating decryption | HIGH |
| FR-16 | The system SHALL generate a unique Watermark ID: `SHA3-256(recipientID \|\| docCID \|\| timestamp \|\| nonce)` | HIGH |
| FR-17 | The system SHALL embed the Watermark ID invisibly into the decrypted PDF | HIGH |
| FR-18 | The system SHALL deliver only the watermarked copy to the recipient | HIGH |
| FR-19 | The raw decrypted document SHALL never be accessible without watermarking | HIGH |
| FR-20 | The recipient SHALL sign the decryption event record with their Dilithium-3 private key | HIGH |

### 4.4 Blockchain Logging

| Req ID | Requirement | Priority |
|---|---|---|
| FR-21 | The system SHALL log every decryption event to Hyperledger Fabric | HIGH |
| FR-22 | Each log entry SHALL contain: eventID, docHash, recipientID, watermarkID, timestamp, Dilithium signature, public key | HIGH |
| FR-23 | The blockchain ledger SHALL be append-only; no update or delete operations SHALL be permitted | HIGH |
| FR-24 | The system SHALL support querying by watermarkID, recipientID, and docHash | HIGH |
| FR-25 | The system SHALL provide a blockchain explorer interface for auditors | MEDIUM |

### 4.5 Attribution Engine

| Req ID | Requirement | Priority |
|---|---|---|
| FR-26 | The system SHALL accept an uploaded leaked PDF for attribution analysis | HIGH |
| FR-27 | The system SHALL extract the embedded Watermark ID from the leaked PDF | HIGH |
| FR-28 | The system SHALL query the blockchain ledger using the extracted Watermark ID | HIGH |
| FR-29 | The system SHALL verify the Dilithium signature in the matched ledger entry | HIGH |
| FR-30 | The system SHALL generate a cryptographic evidence report identifying the recipient | HIGH |
| FR-31 | The evidence report SHALL include: recipient identity, decryption timestamp, docHash, signature verification result | HIGH |

### 4.6 Dashboards & UI

| Req ID | Requirement | Priority |
|---|---|---|
| FR-32 | Sender Dashboard: upload docs, select recipients, view distribution history | HIGH |
| FR-33 | Recipient Dashboard: view available docs, initiate decryption, download watermarked copy | HIGH |
| FR-34 | Investigator Panel: upload leaked doc, view attribution results and evidence report | HIGH |
| FR-35 | Blockchain Explorer: browse all decryption events on the ledger | MEDIUM |
| FR-36 | Admin Panel: manage users and roles | MEDIUM |

---

## 5. Non-Functional Requirements

### 5.1 Performance

| Req ID | Requirement | Target |
|---|---|---|
| NFR-01 | Document encryption (up to 50MB) | < 5 seconds |
| NFR-02 | Watermark injection | < 2 seconds |
| NFR-03 | Blockchain write (decryption event log) | < 3 seconds |
| NFR-04 | Attribution watermark extraction | < 5 seconds |
| NFR-05 | API endpoint response time (p95) | < 500ms |

### 5.2 Reliability

| Req ID | Requirement |
|---|---|
| NFR-06 | System uptime SHALL be ≥ 99.5% during operation |
| NFR-07 | No decryption event SHALL be lost; blockchain logging is transactional |
| NFR-08 | IPFS storage SHALL maintain document integrity via content hashing |

### 5.3 Scalability

| Req ID | Requirement |
|---|---|
| NFR-09 | System SHALL support up to 100 concurrent users |
| NFR-10 | System SHALL support documents up to 100MB in size |
| NFR-11 | Fabric network SHALL be expandable to multiple organizations/peers |

### 5.4 Usability

| Req ID | Requirement |
|---|---|
| NFR-12 | UI SHALL be operable without cryptographic expertise by end users |
| NFR-13 | All cryptographic operations SHALL be transparent to the user |
| NFR-14 | The system SHALL provide clear error messages for unauthorized access attempts |

### 5.5 Maintainability

| Req ID | Requirement |
|---|---|
| NFR-15 | All modules SHALL be independently deployable via Docker |
| NFR-16 | Codebase SHALL follow PEP8 (Python) and ESLint (TypeScript) standards |
| NFR-17 | All critical functions SHALL have unit test coverage ≥ 80% |

---

## 6. System Architecture Requirements

| Req ID | Requirement |
|---|---|
| AR-01 | The system SHALL be composed of independently deployable microservices |
| AR-02 | Services SHALL communicate via RESTful HTTP APIs |
| AR-03 | All inter-service communication SHALL use HTTPS/TLS |
| AR-04 | Document storage SHALL use a private IPFS node (no public IPFS gateway) |
| AR-05 | The system SHALL be deployable via a single `docker-compose up` command |
| AR-06 | Configuration SHALL be managed via environment variables (`.env` file) |

---

## 7. Cryptographic Requirements

| Req ID | Requirement |
|---|---|
| CR-01 | Document encryption SHALL use AES-256-GCM (symmetric) |
| CR-02 | AES key exchange SHALL use Kyber-1024 KEM (NIST PQC standard) |
| CR-03 | Decryption event signing SHALL use Dilithium-3 (NIST PQC standard) |
| CR-04 | Signature verification SHALL use the recipient's registered Dilithium-3 public key |
| CR-05 | Watermark ID generation SHALL use SHA3-256 |
| CR-06 | All random nonces SHALL use cryptographically secure random number generation (CSPRNG) |
| CR-07 | The system SHALL use `liboqs` (Open Quantum Safe) as the PQC library |
| CR-08 | The system SHALL NOT use RSA, ECDSA, or any classical asymmetric scheme for primary operations |

---

## 8. Blockchain Requirements

| Req ID | Requirement |
|---|---|
| BR-01 | The system SHALL use Hyperledger Fabric as the private blockchain/DLT |
| BR-02 | The Fabric network SHALL be permissioned (no public access) |
| BR-03 | The system SHALL NOT use any public blockchain (Ethereum, Bitcoin, etc.) |
| BR-04 | Fabric chaincode SHALL be written in Go |
| BR-05 | The chaincode SHALL expose: `LogDecryption`, `QueryByWatermark`, `QueryByRecipient`, `QueryByDoc` |
| BR-06 | The chaincode SHALL have NO update or delete functions |
| BR-07 | The Fabric network SHALL have at minimum: 1 org, 2 peers, 1 orderer (RAFT) |
| BR-08 | All ledger data SHALL be stored in CouchDB for rich JSON queries |

---

## 9. Watermarking Requirements

| Req ID | Requirement |
|---|---|
| WR-01 | Watermarks SHALL be invisible to the human eye under normal viewing conditions |
| WR-02 | Watermarks SHALL survive digital copying (copy-paste, re-save) |
| WR-03 | Watermarks SHALL be embedded at the moment of decryption, not at upload time |
| WR-04 | Each watermark SHALL be unique per decryption event (not per document) |
| WR-05 | The watermarking engine SHALL use PDF metadata layer + invisible text layer embedding |
| WR-06 | The watermark extraction algorithm SHALL operate on any standard PDF reader output |
| WR-07 | The system SHALL log the watermarkID to the blockchain at the same time as embedding |

---

## 10. External Interface Requirements

### 10.1 User Interface
- Web-based dashboard built with Next.js
- Accessible on modern browsers (Chrome, Firefox, Edge — latest 2 versions)
- Responsive design (desktop-first, min 1280px)

### 10.2 API Interface
- RESTful JSON API (FastAPI / OpenAPI 3.0 spec auto-generated)
- API documentation available at `/docs` (Swagger UI)
- Authentication via Bearer JWT token in `Authorization` header

### 10.3 Blockchain Interface
- Fabric Gateway SDK (Go) for chaincode interaction
- REST proxy layer for frontend-to-blockchain queries

### 10.4 Storage Interface
- IPFS HTTP API on port 5001 for document storage/retrieval
- PostgreSQL on port 5432 for application metadata

---

## 11. Security Requirements

| Req ID | Requirement |
|---|---|
| SR-01 | Private keys SHALL never be transmitted to or stored on the server |
| SR-02 | All API endpoints SHALL require valid JWT authentication (except `/health`, `/auth/register`, `/auth/login`) |
| SR-03 | Admin users SHALL NOT have the ability to modify or delete blockchain records |
| SR-04 | All passwords SHALL be hashed using bcrypt with a minimum cost factor of 12 |
| SR-05 | The system SHALL enforce HTTPS for all external communications |
| SR-06 | IPFS node SHALL be private and inaccessible from outside the Docker network |
| SR-07 | The system SHALL implement rate limiting on all authentication endpoints |
| SR-08 | The system SHALL log all failed authentication attempts |
| SR-09 | Document CIDs SHALL be non-guessable (IPFS content addressing ensures this) |
| SR-10 | The system SHALL validate all file uploads (file type, size, MIME type) |

---

## 12. Technology Stack

| Component | Technology | Version |
|---|---|---|
| **Backend API** | Python + FastAPI | 3.11 / 0.111 |
| **PQC Library** | liboqs-python (Open Quantum Safe) | 0.10.1 |
| **PDF Processing** | PyMuPDF | 1.24.5 |
| **Symmetric Crypto** | Python `cryptography` (AES-256-GCM) | 42.0.8 |
| **Database ORM** | SQLAlchemy (async) | 2.0.30 |
| **Database** | PostgreSQL | 16 |
| **Document Storage** | IPFS (Kubo) | 0.28.0 |
| **Blockchain** | Hyperledger Fabric | 2.5.x |
| **Chaincode Language** | Go | 1.21 |
| **State Database** | CouchDB (Fabric) | 3.3.3 |
| **Frontend** | Next.js (App Router) | 14.x |
| **Frontend Language** | TypeScript | 5.x |
| **Containerization** | Docker + Docker Compose | 26.x |
| **Auth Tokens** | JWT (python-jose) | 3.3.0 |

---

## 13. Constraints & Assumptions

### Constraints
- **No public blockchain:** The system must use a private, permissioned blockchain only.
- **No external cloud services:** All components must run on-premise or in a private network.
- **Post-quantum only:** Classical asymmetric cryptography (RSA, ECC) is not acceptable for primary operations.
- **PDF documents only:** The watermarking engine is designed for PDF format in this version.

### Assumptions
- Recipients possess a device capable of running the web client (modern browser).
- The private key is securely stored by each recipient (e.g., hardware token or secure local storage).
- The Hyperledger Fabric network is managed by a trusted infrastructure team separate from application admins.
- All participating nodes are within a trusted private network.

---

## 14. Glossary

| Term | Definition |
|---|---|
| **KEM** | Key Encapsulation Mechanism — a cryptographic primitive used to securely transmit a symmetric key |
| **Kyber-1024** | NIST-standardized post-quantum KEM algorithm (now FIPS 203 / ML-KEM) |
| **Dilithium-3** | NIST-standardized post-quantum digital signature algorithm (now FIPS 204 / ML-DSA) |
| **PQC** | Post-Quantum Cryptography — cryptographic algorithms resistant to quantum computer attacks |
| **AES-256-GCM** | Advanced Encryption Standard with 256-bit key in Galois/Counter Mode (authenticated encryption) |
| **SHA3-256** | Secure Hash Algorithm 3, 256-bit output — used for watermark ID generation |
| **Watermark ID** | A unique identifier embedded invisibly into a decrypted PDF copy, linking it to a specific decryption event |
| **CID** | Content Identifier — a cryptographic hash used by IPFS to address stored content |
| **DLT** | Distributed Ledger Technology |
| **Hyperledger Fabric** | An enterprise-grade, permissioned private blockchain framework by the Linux Foundation |
| **Chaincode** | Smart contract code deployed on Hyperledger Fabric |
| **Provenance** | A verifiable, tamper-evident record of the origin and history of a document or event |
| **Attribution** | The process of cryptographically identifying the individual responsible for a decryption/leak event |
| **IPFS** | InterPlanetary File System — a distributed, content-addressed file storage protocol |
| **JWT** | JSON Web Token — a compact, self-contained token for authentication |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator |
| **MSP** | Membership Service Provider — manages identities in a Hyperledger Fabric network |
| **HSM** | Hardware Security Module — a physical device for secure key storage |
