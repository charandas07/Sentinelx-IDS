import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import select
from app.database import Base
from app.models.alert import Alert


async def main():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s1:
        s1.add(Alert(attack_type="X", severity="HIGH", src_ip="1.2.3.4", is_simulation=True))
        await s1.commit()
    async with sm() as s2:
        res = await s2.execute(select(Alert))
        print("shared across sessions:", len(res.scalars().all()))
    print("pool class:", engine.pool.__class__.__name__)


asyncio.run(main())