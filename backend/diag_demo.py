"""Diagnostic: run guided scenario and print per-stage results."""
import asyncio, json, logging
logging.basicConfig(level=logging.INFO)
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.database import Base
from app.services.seed import seed_rules
from app.services import demo_simulator
from app.services.traffic_processor import traffic_processor
from app.detection.engine import run_detection, clear_cooldowns
from app.config import settings

settings.DEBUG = True
settings.DEMO_SPEED = 1000.0
URL = "sqlite+aiosqlite:///file:diag_db?mode=memory&cache=shared&uri=true"


async def main():
    eng = create_async_engine(URL, connect_args={"check_same_thread": False, "timeout": 30})
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(eng, expire_on_commit=False)
    async with factory() as db:
        await seed_rules(db)

    events = []

    async def broadcast(t, d):
        events.append({"type": t, "data": d})

    demo_simulator.set_broadcast_callback(broadcast)

    class F:
        def __call__(self):
            return self
        async def __aenter__(self):
            self._s = factory()
            return self._s
        async def __aexit__(self, *a):
            await self._s.close()

    demo_simulator.set_db_factory(F())
    clear_cooldowns()

    stop = asyncio.Event()

    async def worker():
        while not stop.is_set():
            try:
                async with factory() as s:
                    await run_detection(s, traffic_processor, is_simulation=True, broadcast_callback=broadcast)
            except Exception as e:
                print("DETECTION ERR:", e)
            await asyncio.sleep(0.01)

    t = asyncio.create_task(worker())
    summary = await demo_simulator.run_guided_scenario()
    print("RUN1 SUMMARY:", json.dumps(summary, indent=2, default=str))
    events.clear()
    summary = await demo_simulator.run_guided_scenario()
    print("RUN2 SUMMARY:", json.dumps(summary, indent=2, default=str))
    stop.set()
    await t
    for e in events:
        if e["type"] == "demo_stage_result":
            print("STAGE:", e["data"])
    # Dump engine cooldowns + spike-related counters for debugging
    from app.detection import engine as eng_mod
    print("COOLDOWNS:", {f"{k[0]}|{k[1]}": v for k, v in eng_mod._alert_cooldowns.items()})
    # Print all alerts
    async with factory() as s:
        from sqlalchemy import select
        from app.models.alert import Alert
        for a in (await s.execute(select(Alert))).scalars().all():
            print("ALERT:", a.attack_type, a.src_ip, a.timestamp)
    await eng.dispose()

asyncio.run(main())
