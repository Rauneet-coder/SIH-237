from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    init_db is skipped when running under tests (sqlite DATABASE_URL).
    """
    if not settings.DATABASE_URL.startswith("sqlite"):
        await init_db()
    yield


app = FastAPI(
    title="SIH26237 — Cryptographic Attribution & Provenance System",
    description=(
        "Immutable decryption provenance with post-quantum cryptography "
        "and forensic watermarking for Ministry of Defence classified document distribution."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers registered per milestone ─────────────────────────────────
# M1: auth, kms         (uncommented in feature/m1-auth-kms)
# M2: documents         (uncommented in feature/m2-encryption-ipfs)
# M4: blockchain        (uncommented in feature/m4-blockchain-chaincode)
# M6: attribution       (uncommented in feature/m6-attribution-engine)


@app.get("/health", tags=["Health"])
async def health_check():
    """Service health check — used by Docker health checks and load balancers."""
    return {"status": "ok", "service": "SIH26237-Backend", "version": "1.0.0"}
