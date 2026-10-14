"""
Pytest configuration and fixtures.
"""
import asyncio
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from fastapi.testclient import TestClient

from app.database import Base, get_db
from app.main import app
from app.services.seed import seed_rules

from app.config import settings
settings.DEBUG = True

# File-based test DB so concurrent sessions each get their own connection
# (mirrors production where AsyncSessionLocal opens a fresh session/connection
# per context). A shared in-memory DB is used so all connections see the same data.
TEST_DATABASE_URL = "sqlite+aiosqlite:///file:sentinelx_test?mode=memory&cache=shared&uri=true"


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest_asyncio.fixture
async def engine():
    """Per-test engine. Shared-cache in-memory SQLite lets independent sessions
    (demo simulator + detection worker + API) observe each other's commits
    without sharing a single DBAPI connection."""
    eng = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()


@pytest_asyncio.fixture
async def session_factory(engine):
    """Factory that yields fresh AsyncSessions sharing the test engine/DB."""
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def async_db(session_factory):
    """A single session (seeded) for tests / the FastAPI client override."""
    async with session_factory() as session:
        await seed_rules(session)
        yield session


@pytest.fixture
def client(async_db):
    async def _override_get_db():
        yield async_db

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, headers={"Authorization": f"Bearer {settings.SECRET_KEY}"}) as c:
        yield c
    app.dependency_overrides.clear()