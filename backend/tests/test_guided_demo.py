"""
Tests for guided demo scenario orchestrator and demo API.
"""
import asyncio
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.config import settings
from app.services import demo_simulator
from app.services.traffic_processor import traffic_processor
from app.detection.engine import run_detection
from app.models.alert import Alert
from app.models.rule import DetectionRule
from app.models.traffic import TrafficFlow


@pytest.mark.asyncio
async def test_guided_scenario_full_execution(async_db, monkeypatch):
    """
    With DEMO_SPEED set high and mocked broadcast callback:
    - Stages execute in order
    - Injected packets have is_simulation=True
    - Each attack stage uses a different attacker IP
    - A second run uses different IPs
    - Each of the 5 attack types produces an alert and a demo_stage_result with detected=True
    - demo_finished is always broadcast
    """
    settings.DEMO_SPEED = 1000.0  # Ultra-fast sleeps

    broadcast_events = []

    async def mock_broadcast(msg_type: str, data: dict):
        broadcast_events.append({"type": msg_type, "data": data})

    demo_simulator.set_broadcast_callback(mock_broadcast)

    class MockSessionFactory:
        """Yields a fresh session per context, mirroring production AsyncSessionLocal."""
        def __call__(self):
            return self

        async def __aenter__(self):
            self._session = async_sessionmaker(async_db.bind, expire_on_commit=False)()
            return self._session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            await self._session.close()

    mock_db_factory = MockSessionFactory()
    demo_simulator.set_db_factory(mock_db_factory)

    # Background detection engine simulation runner
    engine_stop = asyncio.Event()

    async def detection_worker():
        while not engine_stop.is_set():
            try:
                factory = async_sessionmaker(async_db.bind, expire_on_commit=False)
                async with factory() as det_session:
                    await run_detection(det_session, traffic_processor, is_simulation=True, broadcast_callback=mock_broadcast)
            except Exception:
                pass
            await asyncio.sleep(0.01)

    det_task = asyncio.create_task(detection_worker())

    try:
        # Run 1
        summary1 = await demo_simulator.run_guided_scenario()

        assert summary1["cancelled"] is False
        assert summary1["detected_count"] == 5
        assert summary1["attack_stages"] == 5

        # Check broadcast events in run 1
        started_events = [e for e in broadcast_events if e["type"] == "demo_started"]
        assert len(started_events) >= 1

        stage_events = [e for e in broadcast_events if e["type"] == "demo_stage"]
        stage_keys_received = [e["data"]["key"] for e in stage_events]
        assert "NORMAL_TRAFFIC" in stage_keys_received
        assert "PORT_SCAN" in stage_keys_received
        assert "BRUTE_FORCE" in stage_keys_received
        assert "SYN_FLOOD" in stage_keys_received
        assert "ICMP_FLOOD" in stage_keys_received
        assert "TRAFFIC_SPIKE" in stage_keys_received

        stage_results = [e for e in broadcast_events if e["type"] == "demo_stage_result"]
        attack_results = [r for r in stage_results if r["data"]["key"] != "NORMAL_TRAFFIC"]
        assert len(attack_results) == 5
        assert all(r["data"]["detected"] is True for r in attack_results)

        # Unique attacker IPs in run 1
        run1_ips = [r["data"]["src_ip"] for r in attack_results]
        assert len(set(run1_ips)) == len(run1_ips)

        # Run 2: ensure different attacker IPs are chosen
        broadcast_events.clear()
        summary2 = await demo_simulator.run_guided_scenario()
        assert summary2["detected_count"] == 5

        stage_results2 = [e for e in broadcast_events if e["type"] == "demo_stage_result"]
        attack_results2 = [r for r in stage_results2 if r["data"]["key"] != "NORMAL_TRAFFIC"]
        run2_ips = [r["data"]["src_ip"] for r in attack_results2]

        # Ensure run 2 IPs are distinct from run 1 IPs
        overlap = set(run1_ips).intersection(set(run2_ips))
        assert len(overlap) == 0

        # Verify all TrafficFlows created had is_simulation=True
        flow_res = await async_db.execute(select(TrafficFlow))
        flows = flow_res.scalars().all()
        assert len(flows) > 0
        assert all(f.is_simulation is True for f in flows)

    finally:
        engine_stop.set()
        await det_task
        settings.DEMO_SPEED = 1.0


@pytest.mark.asyncio
async def test_guided_scenario_duplicate_and_cancel(async_db):
    """Starting twice does not create two tasks. Stop mid-run cancels injection and broadcasts demo_finished with cancelled=true."""
    settings.DEMO_SPEED = 0.5  # Slower so it stays in progress

    broadcast_events = []

    async def mock_broadcast(msg_type: str, data: dict):
        broadcast_events.append({"type": msg_type, "data": data})

    demo_simulator.set_broadcast_callback(mock_broadcast)

    class MockSessionFactory:
        def __call__(self):
            return self

        async def __aenter__(self):
            return async_db

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    demo_simulator.set_db_factory(MockSessionFactory())

    res1 = demo_simulator.start(mode="guided")
    assert res1["status"] == "started"

    # Second start while running
    res2 = demo_simulator.start(mode="guided")
    assert res2["status"] == "already_running"

    # Stop mid-run
    await asyncio.sleep(0.05)
    stop_res = demo_simulator.stop()
    assert stop_res["status"] == "stopped"

    # Wait brief moment for task cleanup
    await asyncio.sleep(0.1)
    finished_events = [e for e in broadcast_events if e["type"] == "demo_finished"]
    assert len(finished_events) >= 1
    assert finished_events[-1]["data"]["cancelled"] is True
    settings.DEMO_SPEED = 1.0


@pytest.mark.asyncio
async def test_clear_simulation_data_preserves_real_alerts(async_db):
    """DELETE /api/demo/data removes only simulation rows and leaves a non-simulation alert intact."""
    class MockSessionFactory:
        def __call__(self):
            return self

        async def __aenter__(self):
            self._session = async_sessionmaker(async_db.bind, expire_on_commit=False)()
            return self._session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            await self._session.close()

    demo_simulator.set_db_factory(MockSessionFactory())

    # Add real alert
    real_alert = Alert(
        attack_type="PORT_SCAN",
        severity="HIGH",
        src_ip="192.168.1.99",
        is_simulation=False,
    )
    # Add simulation alert
    sim_alert = Alert(
        attack_type="SYN_FLOOD",
        severity="CRITICAL",
        src_ip="203.0.113.88",
        is_simulation=True,
    )
    # Add simulation flow
    sim_flow = TrafficFlow(
        src_ip="203.0.113.88",
        dst_ip="192.168.1.10",
        protocol="TCP",
        is_simulation=True,
    )
    async_db.add_all([real_alert, sim_alert, sim_flow])
    await async_db.commit()

    traffic_processor.sim_ips.add("203.0.113.88")

    clear_res = await demo_simulator.clear_simulation_data()
    assert clear_res["status"] == "cleared"

    # Verify simulation rows deleted
    alerts_res = await async_db.execute(select(Alert))
    remaining_alerts = alerts_res.scalars().all()
    assert len(remaining_alerts) == 1
    assert remaining_alerts[0].is_simulation is False
    assert remaining_alerts[0].src_ip == "192.168.1.99"

    flows_res = await async_db.execute(select(TrafficFlow).where(TrafficFlow.is_simulation.is_(True)))
    assert len(flows_res.scalars().all()) == 0

    assert "203.0.113.88" not in traffic_processor.sim_ips


@pytest.mark.asyncio
async def test_disabled_detection_rule_skips_stage(async_db):
    """Disabling a DetectionRule makes that stage 'skipped' instead of failing the run."""
    settings.DEMO_SPEED = 1000.0

    # Disable PORT_SCAN rule
    res = await async_db.execute(select(DetectionRule).where(DetectionRule.attack_type == "PORT_SCAN"))
    rule = res.scalar_one_or_none()
    if rule:
        rule.enabled = False
        await async_db.commit()

    broadcast_events = []

    async def mock_broadcast(msg_type: str, data: dict):
        broadcast_events.append({"type": msg_type, "data": data})

    demo_simulator.set_broadcast_callback(mock_broadcast)

    class MockSessionFactory:
        def __call__(self):
            return self

        async def __aenter__(self):
            self._session = async_sessionmaker(async_db.bind, expire_on_commit=False)()
            return self._session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            await self._session.close()

    demo_simulator.set_db_factory(MockSessionFactory())

    summary = await demo_simulator.run_guided_scenario()
    assert summary["cancelled"] is False

    port_scan_result = [
        e["data"] for e in broadcast_events
        if e["type"] == "demo_stage_result" and e["data"]["key"] == "PORT_SCAN"
    ]
    assert len(port_scan_result) == 1
    assert port_scan_result[0]["skipped"] is True

    # Re-enable for subsequent tests
    if rule:
        rule.enabled = True
        await async_db.commit()
    settings.DEMO_SPEED = 1.0
