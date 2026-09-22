"""
Database initialisation using Beanie (async MongoDB ODM).

Why Beanie?
- Models are just Pydantic v2 classes — no migrations, no SQL, no schema files
- Async by default (uses Motor under the hood)
- Validation is automatic via Pydantic

Usage:
    from app.core.database import init_db
    await init_db()   # called once on app startup

Adding a new model:
    1. Create your class in app/models/
    2. Add it to the `document_models` list in init_db()
    That's it — no migration needed.
"""

import motor.motor_asyncio
from beanie import init_beanie

from app.core.config import settings


async def init_db() -> None:
    """
    Connect to MongoDB and initialise Beanie with all document models.

    Beanie automatically creates collections and indexes — no manual setup.
    """
    # Import all models here (add new ones as you create them)
    from app.models.user import User         # M1
    # from app.models.document import Document, KEMCapsule   # uncomment in M2

    client = motor.motor_asyncio.AsyncIOMotorClient(settings.MONGODB_URL)
    database = client[settings.MONGODB_DB_NAME]

    await init_beanie(
        database=database,
        document_models=[
            User,
            # Document,     # add in M2
            # KEMCapsule,   # add in M2
        ],
    )
