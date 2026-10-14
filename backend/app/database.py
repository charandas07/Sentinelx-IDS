"""
Database setup — async SQLAlchemy with SQLite via aiosqlite.
"""
import os
from sqlalchemy import event
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

# Ensure data directory exists
os.makedirs("data", exist_ok=True)
os.makedirs("data/pcaps", exist_ok=True)
os.makedirs("data/exports", exist_ok=True)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False, "timeout": 30},
)

if "sqlite" in settings.DATABASE_URL:
    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        finally:
            cursor.close()

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def init_db():
    """Create all tables and apply safe, additive schema upgrades."""
    from app.models import alert, traffic, ip_stats, rule, event, whitelist, incident  # noqa: F401
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Additive migration for pre-existing databases: new SentinelX 2.0
        # columns are added only when missing. Never drops or rewrites data.
        await conn.run_sync(_upgrade_schema)


# Columns added by SentinelX 2.0 on the pre-existing "alerts" table.
_ALERT_EXTRA_COLUMNS = [
    ("evidence_json", "TEXT"),
    ("flow_id", "VARCHAR(128)"),
    ("incident_id", "INTEGER"),
    ("provenance", "VARCHAR(16) DEFAULT 'live'"),
    ("rule_version", "VARCHAR(16)"),
]


def _upgrade_schema(sync_conn):
    """Idempotent SQLite schema upgrade (ALTER TABLE ADD COLUMN only)."""
    from sqlalchemy import text, inspect

    inspector = inspect(sync_conn)
    if "alerts" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("alerts")}
    for name, ddl_type in _ALERT_EXTRA_COLUMNS:
        if name not in existing:
            sync_conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {name} {ddl_type}"))
    # Index for incident lookups (created after the column exists).
    sync_conn.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_alerts_incident_id ON alerts (incident_id)"
    ))


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
