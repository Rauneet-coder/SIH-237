# Step-by-Step Build Guide — SIH26237
## Every action, every file, every command — from zero to working system

> **For AI Agents & Developers:** Read this top-to-bottom. Build in exact order.  
> Each Milestone has its own Git branch. Merge to `main` only when all tests pass.

---

## Git Branch Strategy

| Branch | Purpose |
|---|---|
| `main` | Stable, demo-ready code only |
| `feature/m0-infrastructure` | Docker Compose + all service containers |
| `feature/m1-auth-kms` | User auth + PQC key management |
| `feature/m2-encryption-ipfs` | Document encryption + IPFS storage |
| `feature/m3-watermarking` | PDF forensic watermark engine |
| `feature/m4-blockchain-chaincode` | Hyperledger Fabric chaincode + Python client |
| `feature/m5-decryption-pipeline` | Core integrated decryption flow |
| `feature/m6-attribution-engine` | Leaked doc attribution system |
| `feature/m7-frontend-dashboards` | Next.js UI for all roles |

### Branch Workflow (follow for every milestone)
```bash
# 1. Switch to the milestone's branch
git checkout feature/m0-infrastructure

# 2. Build the feature (follow steps below)

# 3. Run tests — must all pass
pytest tests/ -v   # (or go test, or npm test)

# 4. Commit with clear message
git add .
git commit -m "feat(m0): add docker-compose with all 8 services"

# 5. Push to remote
git push origin feature/m0-infrastructure

# 6. Merge to main only after tests are green
git checkout main
git merge feature/m0-infrastructure --no-ff -m "merge: M0 infrastructure complete"
git push origin main
```

---

---

# MILESTONE 0 — Infrastructure
**Branch:** `feature/m0-infrastructure`  
**Goal:** `docker-compose up --build` starts ALL 8 services with no errors.

---

## Step 0.1 — Create `.gitignore`

**File:** `.gitignore`
```
# Python
__pycache__/
*.pyc
venv/
.env

# Node
node_modules/
.next/
.env.local

# Fabric
blockchain/network/crypto-config/
blockchain/network/channel-artifacts/

# Misc
*.log
.DS_Store
```

**Commit:** `chore: add .gitignore`

---

## Step 0.2 — Create Environment Template

**File:** `.env.example`
```env
# ── Application ─────────────────────────────────────
SECRET_KEY=REPLACE_WITH_64_CHAR_HEX_RANDOM_STRING
ACCESS_TOKEN_EXPIRE_MINUTES=60

# ── Database ─────────────────────────────────────────
POSTGRES_USER=sih
POSTGRES_PASSWORD=sih_secret
POSTGRES_DB=sih237
DATABASE_URL=postgresql+asyncpg://sih:sih_secret@postgres:5432/sih237

# ── IPFS ─────────────────────────────────────────────
IPFS_HOST=ipfs
IPFS_PORT=5001

# ── Hyperledger Fabric ────────────────────────────────
FABRIC_GATEWAY_HOST=peer0.org1.example.com
FABRIC_GATEWAY_PORT=7051
FABRIC_CHANNEL=provchannel
FABRIC_CHAINCODE=provenance
FABRIC_MSP_ID=Org1MSP
FABRIC_CERT_PATH=/fabric/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem
FABRIC_KEY_PATH=/fabric/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/priv_sk
FABRIC_TLS_CERT_PATH=/fabric/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt

# ── Watermarking ──────────────────────────────────────
WATERMARK_STRENGTH=0.15

# ── Frontend ──────────────────────────────────────────
NEXT_PUBLIC_API_URL=http://localhost:8000/api
CORS_ORIGINS=["http://localhost:3000"]
```

**Command:**
```bash
cp .env.example .env
# Edit .env with your actual SECRET_KEY (generate: openssl rand -hex 32)
```

---

## Step 0.3 — Backend Dockerfile

**File:** `backend/Dockerfile`
```dockerfile
FROM python:3.11-slim AS builder

# System deps for liboqs (post-quantum crypto C library)
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build libssl-dev git build-essential && \
    rm -rf /var/lib/apt/lists/*

# Build and install liboqs C library
RUN git clone --depth=1 --branch main \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
      -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON && \
    ninja -C /tmp/liboqs/build && \
    ninja -C /tmp/liboqs/build install && \
    ldconfig && rm -rf /tmp/liboqs

# Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

---

## Step 0.4 — Frontend Dockerfile

**File:** `frontend/Dockerfile`
```dockerfile
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20-alpine AS runner
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

---

## Step 0.5 — Docker Compose (ALL services)

**File:** `docker-compose.yml`
```yaml
version: '3.8'

networks:
  sih-net:
    driver: bridge

volumes:
  postgres-data:
  ipfs-data:
  couchdb0-data:
  couchdb1-data:
  fabric-data:

services:

  # ── PostgreSQL ────────────────────────────────────────
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks: [sih-net]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ── IPFS ─────────────────────────────────────────────
  ipfs:
    image: ipfs/kubo:v0.28.0
    volumes:
      - ipfs-data:/data/ipfs
    networks: [sih-net]
    ports:
      - "5001:5001"   # API (internal only in prod)
      - "8080:8080"   # Gateway
    healthcheck:
      test: ["CMD", "ipfs", "id"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ── Fabric CouchDB instances ─────────────────────────
  couchdb0:
    image: couchdb:3.3.3
    environment:
      COUCHDB_USER: admin
      COUCHDB_PASSWORD: adminpw
    volumes:
      - couchdb0-data:/opt/couchdb/data
    networks: [sih-net]

  couchdb1:
    image: couchdb:3.3.3
    environment:
      COUCHDB_USER: admin
      COUCHDB_PASSWORD: adminpw
    volumes:
      - couchdb1-data:/opt/couchdb/data
    networks: [sih-net]

  # ── Fabric Orderer ────────────────────────────────────
  orderer:
    image: hyperledger/fabric-orderer:2.5
    environment:
      FABRIC_LOGGING_SPEC: INFO
      ORDERER_GENERAL_LISTENADDRESS: 0.0.0.0
      ORDERER_GENERAL_LISTENPORT: 7050
      ORDERER_GENERAL_LOCALMSPID: OrdererMSP
      ORDERER_GENERAL_LOCALMSPDIR: /var/hyperledger/orderer/msp
      ORDERER_GENERAL_TLS_ENABLED: "true"
      ORDERER_GENERAL_TLS_PRIVATEKEY: /var/hyperledger/orderer/tls/server.key
      ORDERER_GENERAL_TLS_CERTIFICATE: /var/hyperledger/orderer/tls/server.crt
      ORDERER_GENERAL_TLS_ROOTCAS: '[/var/hyperledger/orderer/tls/ca.crt]'
      ORDERER_GENERAL_BOOTSTRAPMETHOD: file
      ORDERER_GENERAL_BOOTSTRAPFILE: /var/hyperledger/orderer/orderer.genesis.block
    volumes:
      - fabric-data:/var/hyperledger/production/orderer
      - ./blockchain/network/channel-artifacts/genesis.block:/var/hyperledger/orderer/orderer.genesis.block
      - ./blockchain/network/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/msp:/var/hyperledger/orderer/msp
      - ./blockchain/network/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls:/var/hyperledger/orderer/tls
    ports:
      - "7050:7050"
    networks:
      sih-net:
        aliases: [orderer.example.com]
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:7050"]
      interval: 30s
      retries: 3

  # ── Fabric Peer 0 ─────────────────────────────────────
  peer0:
    image: hyperledger/fabric-peer:2.5
    environment:
      CORE_VM_ENDPOINT: unix:///host/var/run/docker.sock
      CORE_PEER_ID: peer0.org1.example.com
      CORE_PEER_ADDRESS: peer0.org1.example.com:7051
      CORE_PEER_LISTENADDRESS: 0.0.0.0:7051
      CORE_PEER_LOCALMSPID: Org1MSP
      CORE_PEER_MSPCONFIGPATH: /etc/hyperledger/fabric/msp
      CORE_PEER_TLS_ENABLED: "true"
      CORE_PEER_TLS_CERT_FILE: /etc/hyperledger/fabric/tls/server.crt
      CORE_PEER_TLS_KEY_FILE: /etc/hyperledger/fabric/tls/server.key
      CORE_PEER_TLS_ROOTCERT_FILE: /etc/hyperledger/fabric/tls/ca.crt
      CORE_LEDGER_STATE_STATEDATABASE: CouchDB
      CORE_LEDGER_STATE_COUCHDBCONFIG_COUCHDBADDRESS: couchdb0:5984
      CORE_LEDGER_STATE_COUCHDBCONFIG_USERNAME: admin
      CORE_LEDGER_STATE_COUCHDBCONFIG_PASSWORD: adminpw
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - ./blockchain/network/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp:/etc/hyperledger/fabric/msp
      - ./blockchain/network/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls:/etc/hyperledger/fabric/tls
    ports:
      - "7051:7051"
    networks:
      sih-net:
        aliases: [peer0.org1.example.com]
    depends_on: [orderer, couchdb0]

  # ── Fabric Peer 1 ─────────────────────────────────────
  peer1:
    image: hyperledger/fabric-peer:2.5
    environment:
      CORE_PEER_ID: peer1.org1.example.com
      CORE_PEER_ADDRESS: peer1.org1.example.com:8051
      CORE_PEER_LISTENADDRESS: 0.0.0.0:8051
      CORE_PEER_LOCALMSPID: Org1MSP
      CORE_PEER_TLS_ENABLED: "true"
      CORE_LEDGER_STATE_STATEDATABASE: CouchDB
      CORE_LEDGER_STATE_COUCHDBCONFIG_COUCHDBADDRESS: couchdb1:5984
      CORE_LEDGER_STATE_COUCHDBCONFIG_USERNAME: admin
      CORE_LEDGER_STATE_COUCHDBCONFIG_PASSWORD: adminpw
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - ./blockchain/network/crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/msp:/etc/hyperledger/fabric/msp
      - ./blockchain/network/crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/tls:/etc/hyperledger/fabric/tls
    ports:
      - "8051:8051"
    networks:
      sih-net:
        aliases: [peer1.org1.example.com]
    depends_on: [orderer, couchdb1]

  # ── FastAPI Backend ────────────────────────────────────
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    env_file: .env
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/app
      - ./blockchain/network/crypto-config:/fabric/crypto-config:ro
    networks: [sih-net]
    depends_on:
      postgres:
        condition: service_healthy
      ipfs:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 5

  # ── Next.js Frontend ──────────────────────────────────
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    env_file: .env
    ports:
      - "3000:3000"
    volumes:
      - ./frontend:/app
      - /app/node_modules
    networks: [sih-net]
    depends_on:
      backend:
        condition: service_healthy
```

---

## Step 0.6 — Scaffold Next.js Frontend

```bash
cd /Users/rauneetsingh/Developer/SIH_237
npx create-next-app@14 frontend \
  --typescript \
  --app \
  --no-tailwind \
  --eslint \
  --no-src-dir \
  --import-alias "@/*"
```

---

## Step 0.7 — Backend App Skeleton

Create these empty `__init__.py` files so Python recognizes the packages:
```bash
touch backend/app/__init__.py
touch backend/app/api/__init__.py
touch backend/app/core/__init__.py
touch backend/app/models/__init__.py
touch backend/app/services/__init__.py
touch backend/tests/__init__.py
```

Create `backend/app/main.py` (FastAPI app with router stubs):
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.core.config import settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield  # DB init comes in M1

app = FastAPI(
    title="SIH26237 — Cryptographic Provenance System",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "SIH26237-Backend"}
```

Create `backend/app/core/config.py`:
```python
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    SECRET_KEY: str = "dev_secret_change_me"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    DATABASE_URL: str = "postgresql+asyncpg://sih:sih_secret@postgres:5432/sih237"
    IPFS_HOST: str = "ipfs"
    IPFS_PORT: int = 5001
    FABRIC_GATEWAY_HOST: str = "peer0.org1.example.com"
    FABRIC_GATEWAY_PORT: int = 7051
    FABRIC_CHANNEL: str = "provchannel"
    FABRIC_CHAINCODE: str = "provenance"
    FABRIC_MSP_ID: str = "Org1MSP"
    FABRIC_CERT_PATH: str = ""
    FABRIC_KEY_PATH: str = ""
    FABRIC_TLS_CERT_PATH: str = ""
    WATERMARK_STRENGTH: float = 0.15
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    class Config:
        env_file = ".env"

settings = Settings()
```

---

## Step 0.8 — Verify

```bash
docker-compose up --build
# Wait ~5 minutes for first build

# In another terminal:
curl http://localhost:8000/health
# Expected: {"status":"ok","service":"SIH26237-Backend"}

curl http://localhost:3000
# Expected: Next.js default page
```

## Step 0.9 — Commit and Merge

```bash
git add .
git commit -m "feat(m0): docker-compose, all services, FastAPI skeleton, Next.js scaffold"
git push origin feature/m0-infrastructure

git checkout main
git merge feature/m0-infrastructure --no-ff -m "merge: M0 infrastructure ✅"
git push origin main
```

---

---

# MILESTONE 1 — Authentication + Key Management
**Branch:** `feature/m1-auth-kms`  
**Goal:** Register generates Kyber + Dilithium keypairs. Login returns JWT. All routes protected.

```bash
git checkout feature/m1-auth-kms
```

---

## Step 1.1 — Database Engine

**File:** `backend/app/core/database.py`
```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
```

---

## Step 1.2 — Database Models

**File:** `backend/app/models/user.py`
```python
import uuid
from datetime import datetime
from sqlalchemy import String, Enum, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base
import enum

class UserRole(str, enum.Enum):
    sender = "sender"
    recipient = "recipient"
    investigator = "investigator"
    admin = "admin"

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.recipient)
    kyber_public_key: Mapped[str] = mapped_column(String(4096), nullable=True)    # base64
    dilithium_public_key: Mapped[str] = mapped_column(String(4096), nullable=True) # base64
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(default=True)
```

---

## Step 1.3 — PQC Crypto Core

**File:** `backend/app/core/crypto.py`
```python
"""
Low-level post-quantum cryptography bindings using liboqs.
All functions return raw bytes. Base64 encoding handled by service layer.
"""
import oqs
from typing import Tuple


def generate_kyber_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a Kyber-1024 keypair for key encapsulation.

    Returns:
        (public_key, secret_key) — both as raw bytes.
        Public key: 1568 bytes. Secret key: 3168 bytes.
    """
    kem = oqs.KeyEncapsulation("Kyber1024")
    public_key: bytes = kem.generate_keypair()
    secret_key: bytes = kem.export_secret_key()
    return public_key, secret_key


def generate_dilithium_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a Dilithium-3 keypair for digital signatures.

    Returns:
        (verify_key, sign_key) — both as raw bytes.
        Verify key: 1952 bytes. Sign key: 4000 bytes.
    """
    sig = oqs.Signature("Dilithium3")
    verify_key: bytes = sig.generate_keypair()
    sign_key: bytes = sig.export_secret_key()
    return verify_key, sign_key


def dilithium_sign(message: bytes, secret_key: bytes) -> bytes:
    """Sign a message with Dilithium-3 secret key."""
    sig = oqs.Signature("Dilithium3", secret_key)
    return sig.sign(message)


def dilithium_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a Dilithium-3 signature. Returns True if valid."""
    try:
        verifier = oqs.Signature("Dilithium3")
        return verifier.verify(message, signature, public_key)
    except Exception:
        return False


def kyber_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using a Kyber-1024 public key.

    Returns:
        (ciphertext, shared_secret) — ciphertext: 1568 bytes, shared_secret: 32 bytes.
    """
    kem = oqs.KeyEncapsulation("Kyber1024")
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def kyber_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Recover shared secret from Kyber-1024 ciphertext using secret key.

    Returns:
        shared_secret (32 bytes) — the recovered AES key material.
    """
    kem = oqs.KeyEncapsulation("Kyber1024", secret_key)
    return kem.decap_secret(ciphertext)
```

---

## Step 1.4 — Security Utilities (JWT + Passwords)

**File:** `backend/app/core/security.py`
```python
import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)
bearer_scheme = HTTPBearer()


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
):
    """FastAPI dependency — validates JWT and returns the User object."""
    from app.models.user import User  # local import to avoid circular

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, settings.SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    return user
```

---

## Step 1.5 — Auth API Route

**File:** `backend/app/api/auth.py`
```python
import base64
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr

from app.core.database import get_db
from app.core.security import get_password_hash, verify_password, create_access_token
from app.core.crypto import generate_kyber_keypair, generate_dilithium_keypair
from app.models.user import User, UserRole

router = APIRouter()


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.recipient


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@router.post("/register", status_code=201)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Register a new user. Generates PQC keypairs. Private keys returned ONCE."""
    # Check existing
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    # Generate PQC keypairs
    kyber_pub, kyber_priv = generate_kyber_keypair()
    dilithium_pub, dilithium_priv = generate_dilithium_keypair()

    # Create user — store ONLY public keys
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
        role=payload.role,
        kyber_public_key=base64.b64encode(kyber_pub).decode(),
        dilithium_public_key=base64.b64encode(dilithium_pub).decode(),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # Return private keys ONCE — server immediately discards them
    return {
        "user_id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "keypairs": {
            "kyber": {
                "public_key": base64.b64encode(kyber_pub).decode(),
                "private_key": base64.b64encode(kyber_priv).decode(),
            },
            "dilithium": {
                "public_key": base64.b64encode(dilithium_pub).decode(),
                "private_key": base64.b64encode(dilithium_priv).decode(),
            },
        },
        "warning": "SAVE PRIVATE KEYS NOW — they will never be shown again.",
    }


@router.post("/login")
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate and return a JWT access token."""
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    token = create_access_token({"sub": str(user.id), "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600,
        "user": {"id": str(user.id), "username": user.username, "role": user.role},
    }
```

---

## Step 1.6 — KMS API Route

**File:** `backend/app/api/kms.py`
```python
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User

router = APIRouter()


@router.get("/my-keys")
async def get_my_keys(current_user: User = Depends(get_current_user)):
    """Return the current user's registered public keys."""
    return {
        "user_id": str(current_user.id),
        "kyber_public_key": current_user.kyber_public_key,
        "dilithium_public_key": current_user.dilithium_public_key,
    }


@router.get("/users")
async def list_users(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all users with their public keys. Sender role required."""
    if current_user.role not in ("sender", "admin"):
        from fastapi import HTTPException
        raise HTTPException(403, "Sender role required")

    result = await db.execute(select(User).where(User.is_active == True))
    users = result.scalars().all()
    return [
        {
            "user_id": str(u.id),
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "kyber_public_key": u.kyber_public_key,
        }
        for u in users
    ]
```

---

## Step 1.7 — Register Routers in main.py

Update `backend/app/main.py`:
```python
from app.api import auth, kms
from app.core.database import init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(kms.router,  prefix="/api/kms",  tags=["Key Management"])
```

---

## Step 1.8 — Write Unit Tests

**File:** `backend/tests/test_crypto.py`
```python
import pytest
from app.core.crypto import (
    generate_kyber_keypair, kyber_encapsulate, kyber_decapsulate,
    generate_dilithium_keypair, dilithium_sign, dilithium_verify
)

def test_kyber_keygen_sizes():
    pub, priv = generate_kyber_keypair()
    assert len(pub) == 1568
    assert len(priv) == 3168

def test_kyber_encap_decap_roundtrip():
    pub, priv = generate_kyber_keypair()
    ciphertext, shared_secret = kyber_encapsulate(pub)
    recovered = kyber_decapsulate(ciphertext, priv)
    assert shared_secret == recovered
    assert len(shared_secret) == 32

def test_dilithium_keygen_sizes():
    vk, sk = generate_dilithium_keypair()
    assert len(vk) == 1952
    assert len(sk) == 4000

def test_dilithium_sign_verify():
    vk, sk = generate_dilithium_keypair()
    message = b"decryption_event_record"
    sig = dilithium_sign(message, sk)
    assert dilithium_verify(message, sig, vk) is True

def test_dilithium_verify_tampered_message():
    vk, sk = generate_dilithium_keypair()
    sig = dilithium_sign(b"original", sk)
    assert dilithium_verify(b"tampered", sig, vk) is False
```

**File:** `backend/tests/test_auth.py`
```python
import pytest
import httpx

BASE = "http://localhost:8000/api"

def test_register_returns_private_keys():
    r = httpx.post(f"{BASE}/auth/register", json={
        "username": "test_user", "email": "test@mod.gov.in",
        "password": "Test123!", "role": "recipient"
    })
    assert r.status_code == 201
    data = r.json()
    assert "keypairs" in data
    assert "private_key" in data["keypairs"]["kyber"]

def test_login_returns_jwt():
    r = httpx.post(f"{BASE}/auth/login", json={
        "email": "test@mod.gov.in", "password": "Test123!"
    })
    assert r.status_code == 200
    assert "access_token" in r.json()

def test_protected_route_requires_jwt():
    r = httpx.get(f"{BASE}/kms/my-keys")
    assert r.status_code == 403  # No token
```

---

## Step 1.9 — Commit and Merge

```bash
pytest backend/tests/test_crypto.py backend/tests/test_auth.py -v
# All green ✅

git add .
git commit -m "feat(m1): auth registration with PQC keypair generation, JWT login, KMS endpoints"
git push origin feature/m1-auth-kms

git checkout main
git merge feature/m1-auth-kms --no-ff -m "merge: M1 Auth + KMS ✅"
git push origin main
```

---

---

# MILESTONE 2 — Document Encryption + IPFS
**Branch:** `feature/m2-encryption-ipfs`

```bash
git checkout feature/m2-encryption-ipfs
```

## Steps (Summary — full code in docs/ARCHITECTURE.md)

| Step | File | What |
|---|---|---|
| 2.1 | `app/models/document.py` | Document, KEMCapsule ORM models |
| 2.2 | `app/services/crypto_service.py` | AES-256-GCM encrypt/decrypt + Kyber KEM wrap |
| 2.3 | `app/services/ipfs_service.py` | IPFS upload/download via `ipfshttpclient` |
| 2.4 | `app/api/documents.py` | POST /docs/upload, GET /docs/list |
| 2.5 | `tests/test_encryption.py` | AES roundtrip, KEM roundtrip, IPFS upload |
| 2.6 | Commit + Merge | `feat(m2): document encryption + IPFS storage` |

---

# MILESTONE 3 — Watermarking Engine
**Branch:** `feature/m3-watermarking`

```bash
git checkout feature/m3-watermarking
```

| Step | File | What |
|---|---|---|
| 3.1 | `app/services/watermark_service.py` | `embed_watermark()`, `extract_watermark()`, `generate_watermark_id()` |
| 3.2 | `tests/test_watermark.py` | Roundtrip, no-watermark, uniqueness tests |
| 3.3 | Commit + Merge | `feat(m3): invisible PDF forensic watermarking engine` |

---

# MILESTONE 4 — Blockchain Chaincode
**Branch:** `feature/m4-blockchain-chaincode`

```bash
git checkout feature/m4-blockchain-chaincode
```

| Step | File | What |
|---|---|---|
| 4.1 | `blockchain/chaincode/provenance/go.mod` | Go module init |
| 4.2 | `blockchain/chaincode/provenance/provenance.go` | LogDecryption, QueryByWatermark, QueryByRecipient, QueryByDoc |
| 4.3 | `blockchain/chaincode/provenance/provenance_test.go` | Go unit tests |
| 4.4 | `blockchain/network/configtx/configtx.yaml` | Fabric channel config |
| 4.5 | `blockchain/scripts/generate-crypto.sh` | cryptogen script |
| 4.6 | `blockchain/scripts/deploy-chaincode.sh` | Deploy script |
| 4.7 | `app/services/fabric_service.py` | Python Fabric Gateway client |
| 4.8 | `app/api/blockchain.py` | GET /blockchain/events endpoints |
| 4.9 | `tests/test_fabric.py` | Log + query integration tests |
| 4.10 | Commit + Merge | `feat(m4): Fabric chaincode + Python gateway client` |

---

# MILESTONE 5 — Decryption Pipeline (Core Feature)
**Branch:** `feature/m5-decryption-pipeline`

```bash
git checkout feature/m5-decryption-pipeline
```

| Step | File | What |
|---|---|---|
| 5.1 | `app/api/documents.py` | POST /docs/decrypt/{id} — integrates M2+M3+M4 |
| 5.2 | `app/services/document_service.py` | Orchestration logic |
| 5.3 | `tests/test_decryption_pipeline.py` | End-to-end integration test |
| 5.4 | Commit + Merge | `feat(m5): integrated decryption pipeline — decrypt+watermark+log` |

---

# MILESTONE 6 — Attribution Engine
**Branch:** `feature/m6-attribution-engine`

```bash
git checkout feature/m6-attribution-engine
```

| Step | File | What |
|---|---|---|
| 6.1 | `app/services/attribution_service.py` | Extract watermark → query blockchain → verify sig → report |
| 6.2 | `app/api/attribution.py` | POST /attribution/analyze |
| 6.3 | `tests/test_attribution.py` | Full attribution integration test |
| 6.4 | Commit + Merge | `feat(m6): cryptographic attribution engine` |

---

# MILESTONE 7 — Frontend Dashboards
**Branch:** `feature/m7-frontend-dashboards`

```bash
git checkout feature/m7-frontend-dashboards
```

| Step | Page | What |
|---|---|---|
| 7.1 | `lib/api.ts` | All fetch() wrappers for API |
| 7.2 | `lib/crypto.ts` | liboqs-js WebAssembly PQC in browser |
| 7.3 | `app/(auth)/login/page.tsx` | Login form |
| 7.4 | `app/(auth)/register/page.tsx` | Register + auto-download private keys |
| 7.5 | `app/dashboard/sender/page.tsx` | Upload + manage docs |
| 7.6 | `app/dashboard/recipient/page.tsx` | Decrypt + download watermarked PDF |
| 7.7 | `app/dashboard/investigator/page.tsx` | Upload leaked doc + view attribution |
| 7.8 | `app/blockchain/page.tsx` | Blockchain ledger explorer |
| 7.9 | Commit + Merge | `feat(m7): all frontend dashboards` |

---

---

# Final Demo Sequence

Run this flow to demonstrate all features working end-to-end:

```bash
# 1. Start everything
docker-compose up --build

# 2. Register Sender
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"col_verma","email":"verma@mod.gov.in","password":"Secure123!","role":"sender"}'
# Save: kyber_private_key, dilithium_private_key

# 3. Register Recipient
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"gen_sharma","email":"sharma@mod.gov.in","password":"Secure123!","role":"recipient"}'
# Save: kyber_private_key, dilithium_private_key

# 4. Login as Sender → get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -d '{"email":"verma@mod.gov.in","password":"Secure123!"}' | jq -r .access_token)

# 5. Upload classified document
curl -X POST http://localhost:8000/api/docs/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@classified_briefing.pdf" \
  -F "title=Operation XYZ Briefing" \
  -F 'recipient_ids=["<gen_sharma_uuid>"]'

# 6. Login as Recipient → decrypt document
# (sends dilithium signature + decapsulated AES key)
# → Downloads watermarked_briefing.pdf

# 7. Register Investigator, login
# 8. Upload watermarked_briefing.pdf to /api/attribution/analyze
# → Returns: "Leaked by gen_sharma, decrypted at 19:30 IST, signature VERIFIED ✅"

# 9. View blockchain explorer at http://localhost:3000/blockchain
# → Immutable event visible with all cryptographic fields
```

---

## Branch Status Tracker

| Branch | Status | Tests |
|---|---|---|
| `feature/m0-infrastructure` | ⬜ Not started | — |
| `feature/m1-auth-kms` | ⬜ Not started | — |
| `feature/m2-encryption-ipfs` | ⬜ Not started | — |
| `feature/m3-watermarking` | ⬜ Not started | — |
| `feature/m4-blockchain-chaincode` | ⬜ Not started | — |
| `feature/m5-decryption-pipeline` | ⬜ Not started | — |
| `feature/m6-attribution-engine` | ⬜ Not started | — |
| `feature/m7-frontend-dashboards` | ⬜ Not started | — |

> Update this table as you complete each milestone.
