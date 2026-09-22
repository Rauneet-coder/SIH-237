from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    # ── Application ──────────────────────────────────────
    APP_NAME: str = "SIH26237-Provenance-System"
    SECRET_KEY: str = "dev_secret_change_me_in_production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── Database ─────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://sih:sih_secret@postgres:5432/sih237"

    # ── IPFS ─────────────────────────────────────────────
    IPFS_HOST: str = "ipfs"
    IPFS_PORT: int = 5001

    # ── Hyperledger Fabric ────────────────────────────────
    FABRIC_GATEWAY_HOST: str = "peer0.org1.example.com"
    FABRIC_GATEWAY_PORT: int = 7051
    FABRIC_CHANNEL: str = "provchannel"
    FABRIC_CHAINCODE: str = "provenance"
    FABRIC_MSP_ID: str = "Org1MSP"
    FABRIC_CERT_PATH: str = ""
    FABRIC_KEY_PATH: str = ""
    FABRIC_TLS_CERT_PATH: str = ""

    # ── Watermarking ──────────────────────────────────────
    WATERMARK_STRENGTH: float = 0.15

    # ── CORS ──────────────────────────────────────────────
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)


settings = Settings()
