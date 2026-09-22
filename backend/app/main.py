from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    - init_db() connects to MongoDB and registers Beanie models.
    - Skipped in test mode (MONGODB_URL contains 'mock' or not set).
    """
    if "mock" not in settings.MONGODB_URL:
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

# ── Routers added per milestone ───────────────────────────────────────
# M1:  from app.api import auth, kms
#      app.include_router(auth.router,  prefix="/api/auth", tags=["Auth"])
#      app.include_router(kms.router,   prefix="/api/kms",  tags=["KMS"])
# M2:  documents router
# M4:  blockchain router
# M6:  attribution router


@app.get("/health", tags=["Health"])
async def health_check():
    """Service health check — used by Docker and load balancers."""
    return {"status": "ok", "service": "SIH26237-Backend", "version": "1.0.0"}
