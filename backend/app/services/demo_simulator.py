"""
Demo Mode Simulator & Guided Scenario Orchestrator
Generates realistic synthetic traffic and attack events.
All records are marked is_simulation=True.
"""
import asyncio
import logging
import random
import socket
import time
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List, Set

from sqlalchemy import select, delete

from app.config import settings
from app.services.traffic_processor import traffic_processor
from app.models.rule import DetectionRule
from app.models.alert import Alert
from app.models.traffic import TrafficFlow
from app.models.ip_stats import IPStatistics
from app.detection import engine

logger = logging.getLogger(__name__)

_active = False
_mode = "idle"  # "idle" | "guided" | "continuous"
_task: Optional[asyncio.Task] = None
_run_lock = asyncio.Lock()

# Guided scenario state
_run_id: Optional[str] = None
_current_step: int = 0
_total_steps: int = 7
_current_stage_key: Optional[str] = None
_progress_pct: int = 0

# Track historical IPs used across runs in this process to guarantee freshness
_used_scenario_ips: Set[str] = set()


def _auto_detect_local_ips() -> List[str]:
    """Detect real local IP addresses from network interfaces."""
    ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if ":" not in addr and not addr.startswith("127."):
                ips.append(addr)
    except Exception:
        pass
    try:
        from scapy.config import conf
        from scapy.layers.inet import get_if_addr
        iface_ip = get_if_addr(conf.iface)
        if iface_ip and iface_ip != "0.0.0.0":
            ips.append(iface_ip)
    except Exception:
        pass
    return list(set(ips))


def _build_internal_ips() -> List[str]:
    """Build internal IP pool including the machine's real local IPs."""
    base = [f"192.168.1.{i}" for i in range(1, 20)] + [f"10.0.0.{i}" for i in range(1, 10)]
    real_locals = _auto_detect_local_ips()
    all_ips = list(base)
    for ip in real_locals:
        if ip not in all_ips:
            all_ips.append(ip)
    return all_ips


# Realistic IP pools (auto-enriched with machine's real local IPs)
INTERNAL_IPS = _build_internal_ips()
EXTERNAL_IPS = [
    "45.33.32.156", "198.51.100.42", "203.0.113.5", "185.220.101.1",
    "1.1.1.1", "8.8.8.8", "104.21.45.67", "172.67.68.91", "91.134.213.25",
    "23.21.55.191", "54.161.85.109", "37.49.224.100",
]
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
COMMON_PORTS = [22, 21, 23, 80, 443, 3389, 5900, 8080, 53, 25, 110, 143, 3306, 5432]

_broadcast_callback = None
_db_session_factory = None

STAGES = [
    {
        "key": "NORMAL_TRAFFIC",
        "title": "Normal Baseline Traffic",
        "description": "Learning what normal looks like.",
        "detection_rule_text": "Observes benign HTTP/HTTPS/DNS traffic to calibrate baseline.",
        "duration_s": 10,
    },
    {
        "key": "PORT_SCAN",
        "title": "TCP SYN Port Scan",
        "description": "Reconnaissance attack scanning multiple ports to find open services.",
        "detection_rule_text": "SYN-only packets to >= 20 distinct ports within 10s window.",
        "duration_s": 8,
    },
    {
        "key": "BRUTE_FORCE",
        "title": "SSH Authentication Brute Force",
        "description": "Repeated connection attempts to crack SSH authentication credentials.",
        "detection_rule_text": ">= 10 SYN attempts to auth port (22:SSH) within 30s window.",
        "duration_s": 8,
    },
    {
        "key": "SYN_FLOOD",
        "title": "TCP SYN Flood DoS",
        "description": "High-volume half-open TCP connection flood exhausting system resources.",
        "detection_rule_text": ">= 100 SYN packets from a single source within 5s window.",
        "duration_s": 8,
    },
    {
        "key": "ICMP_FLOOD",
        "title": "ICMP Ping Flood DoS",
        "description": "Volumetric ICMP echo request flood saturating network bandwidth.",
        "detection_rule_text": ">= 50 ICMP packets from a single source within 5s window.",
        "duration_s": 8,
    },
    {
        "key": "TRAFFIC_SPIKE",
        "title": "Volumetric DDoS Spike",
        "description": "Multi-source volumetric DDoS spike anomalous against established baseline.",
        "detection_rule_text": "Global inbound PPS exceeds baseline x 3.0 multiplier x 2.",
        "duration_s": 10,
    },
    {
        "key": "SUMMARY",
        "title": "Scenario Complete",
        "description": "Demo scenario completed successfully.",
        "detection_rule_text": "All detection algorithms evaluated against real-time pipeline.",
        "duration_s": 0,
    },
]


def set_broadcast_callback(cb):
    global _broadcast_callback
    _broadcast_callback = cb


def set_db_factory(factory):
    global _db_session_factory
    _db_session_factory = factory


def is_active() -> bool:
    return _active


def get_status() -> dict:
    return {
        "active": _active,
        "mode": _mode,
        "run_id": _run_id,
        "step": _current_step,
        "total": _total_steps,
        "stage_key": _current_stage_key,
        "progress_pct": _progress_pct,
    }


def _get_demo_speed() -> float:
    try:
        speed = float(getattr(settings, "DEMO_SPEED", 1.0))
        return speed if speed > 0 else 1.0
    except Exception:
        return 1.0


async def _sleep(seconds: float):
    speed = _get_demo_speed()
    await asyncio.sleep(seconds / speed)


def _generate_unique_attacker_ip() -> str:
    """Pick an unused attacker IP from 198.51.100.0/24 or 203.0.113.0/24."""
    for _ in range(1000):
        if random.random() < 0.5:
            ip = f"198.51.100.{random.randint(10, 250)}"
        else:
            ip = f"203.0.113.{random.randint(10, 250)}"
        if ip not in _used_scenario_ips:
            _used_scenario_ips.add(ip)
            return ip
    # Fallback if pool depleted in long tests
    ip = f"198.51.100.{random.randint(1, 254)}"
    _used_scenario_ips.add(ip)
    return ip


async def _get_rule_effective(attack_type: str) -> Dict[str, Any]:
    """Retrieve rule threshold and enabled status from DB, falling back to settings."""
    enabled = True
    threshold = None
    window = None

    if _db_session_factory:
        try:
            async with _db_session_factory() as db:
                res = await db.execute(select(DetectionRule).where(DetectionRule.attack_type == attack_type))
                rule = res.scalar_one_or_none()
                if rule:
                    enabled = rule.enabled
                    threshold = rule.threshold
                    window = rule.time_window
        except Exception as e:
            logger.debug(f"Error fetching rule {attack_type}: {e}")

    # Settings fallback
    if threshold is None or window is None:
        if attack_type == "PORT_SCAN":
            threshold = threshold or settings.PORT_SCAN_THRESHOLD
            window = window or settings.PORT_SCAN_WINDOW
        elif attack_type == "BRUTE_FORCE":
            threshold = threshold or settings.BRUTE_FORCE_THRESHOLD
            window = window or settings.BRUTE_FORCE_WINDOW
        elif attack_type == "SYN_FLOOD":
            threshold = threshold or settings.SYN_FLOOD_THRESHOLD
            window = window or settings.SYN_FLOOD_WINDOW
        elif attack_type == "ICMP_FLOOD":
            threshold = threshold or settings.ICMP_FLOOD_THRESHOLD
            window = window or settings.ICMP_FLOOD_WINDOW
        elif attack_type in ("TRAFFIC_SPIKE", "DOS_PATTERN"):
            threshold = threshold or settings.TRAFFIC_SPIKE_MULTIPLIER
            window = window or 10

    return {"enabled": enabled, "threshold": threshold, "time_window": window}


async def _emit_packet_batch(packets: List[dict]):
    """Ingest packet list into processor and DB, and broadcast traffic event."""
    for p in packets:
        await traffic_processor.process(p)

    if _db_session_factory:
        async with _db_session_factory() as db:
            for p in packets:
                flow = TrafficFlow(**p)
                db.add(flow)
            await db.commit()

    if _broadcast_callback:
        await _broadcast_callback("traffic", {
            "packets": [
                {
                    "src_ip": p["src_ip"],
                    "dst_ip": p["dst_ip"],
                    "protocol": p["protocol"],
                    "src_port": p.get("src_port"),
                    "dst_port": p.get("dst_port"),
                    "packet_size": p.get("packet_size", 64),
                    "status": p.get("status", "NORMAL"),
                    "timestamp": p["timestamp"].isoformat() if hasattr(p["timestamp"], "isoformat") else str(p["timestamp"]),
                    "is_simulation": True,
                }
                for p in packets[:10]
            ],
            "pps": len(packets),
        })


async def run_guided_scenario() -> dict:
    """Run the deterministic guided demo scenario as one asyncio task."""
    global _active, _mode, _run_id, _current_step, _total_steps, _current_stage_key, _progress_pct, _task

    run_id = f"demo_{uuid.uuid4().hex[:8]}"
    _run_id = run_id
    _active = True
    _mode = "guided"
    _total_steps = len(STAGES)
    _current_step = 0
    _progress_pct = 0

    logger.info(f"Starting guided demo scenario run={run_id}")

    # Ensure baseline is primed if not already ready so spike/dos checks succeed
    if not traffic_processor.is_warmup_done():
        traffic_processor.prime_baseline(20.0, samples=30)

    if _broadcast_callback:
        await _broadcast_callback("demo_started", {
            "run_id": run_id,
            "total_steps": _total_steps,
            "stages": [
                {
                    "key": s["key"],
                    "title": s["title"],
                    "description": s["description"],
                    "detection_rule_text": s["detection_rule_text"],
                }
                for s in STAGES
            ],
        })

    results = []
    total_alerts_count = 0
    cancelled = False

    try:
        for idx, stage in enumerate(STAGES):
            if not _active:
                cancelled = True
                break

            _current_step = idx
            _current_stage_key = stage["key"]
            _progress_pct = int((idx / (_total_steps - 1)) * 100) if _total_steps > 1 else 0

            if _broadcast_callback:
                await _broadcast_callback("demo_stage", {
                    "run_id": run_id,
                    "step": idx,
                    "total": _total_steps,
                    "key": stage["key"],
                    "title": stage["title"],
                    "description": stage["description"],
                    "progress_pct": _progress_pct,
                })

            stage_key = stage["key"]
            stage_start_time = datetime.utcnow()

            # ── STAGE 0: NORMAL_TRAFFIC ─────────────────────────────────────
            if stage_key == "NORMAL_TRAFFIC":
                # ~10s of steady 15-25 pps normal traffic in small batches
                batches = 10
                for _ in range(batches):
                    if not _active:
                        cancelled = True
                        break
                    batch_pkts = []
                    count = random.randint(15, 25)
                    now = datetime.utcnow()
                    for _ in range(count):
                        src = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
                        dst = random.choice(INTERNAL_IPS)
                        proto = random.choice(["TCP", "UDP", "HTTP", "HTTPS", "DNS"])
                        dport = random.choice([80, 443, 53, 8080])
                        batch_pkts.append({
                            "src_ip": src,
                            "dst_ip": dst,
                            "src_port": random.randint(1024, 65535),
                            "dst_port": dport,
                            "protocol": proto,
                            "packet_size": random.randint(64, 1400),
                            "flags": "PA" if proto in ("TCP", "HTTP", "HTTPS") else None,
                            "status": "NORMAL",
                            "is_simulation": True,
                            "timestamp": now,
                        })
                    await _emit_packet_batch(batch_pkts)
                    await _sleep(1.0)
                continue

            # ── STAGE 6: SUMMARY ───────────────────────────────────────────
            elif stage_key == "SUMMARY":
                await _sleep(1.0)
                break

            # ── ATTACK STAGES (1 to 5) ──────────────────────────────────────
            # Check rule enabled state
            rule_info = await _get_rule_effective(stage_key)
            if not rule_info["enabled"]:
                logger.info(f"Skipping stage {stage_key}: rule disabled")
                stage_res = {
                    "run_id": run_id,
                    "key": stage_key,
                    "detected": False,
                    "skipped": True,
                    "latency_s": None,
                    "alert_id": None,
                    "attack_type": stage_key,
                    "src_ip": None,
                }
                results.append(stage_res)
                if _broadcast_callback:
                    await _broadcast_callback("demo_stage_result", stage_res)
                await _sleep(1.5)
                continue

            attacker_ip = _generate_unique_attacker_ip()
            target_ip = random.choice(INTERNAL_IPS)
            effective_threshold = rule_info["threshold"] or 10

            first_packet_time = time.time()

            # Execute traffic generation in small progressive batches
            if stage_key == "PORT_SCAN":
                # SYN-only to ~40 distinct ports sent across 6 batches
                scan_ports_count = max(int(effective_threshold * 1.5), 35)
                ports_list = random.sample(range(1024, 65000), scan_ports_count)
                batch_size = max(1, len(ports_list) // 6)
                for b_i in range(0, len(ports_list), batch_size):
                    if not _active:
                        cancelled = True
                        break
                    chunk = ports_list[b_i:b_i + batch_size]
                    now = datetime.utcnow()
                    pkts = [
                        {
                            "src_ip": attacker_ip,
                            "dst_ip": target_ip,
                            "src_port": random.randint(1024, 65535),
                            "dst_port": dp,
                            "protocol": "TCP",
                            "packet_size": 64,
                            "flags": "S",
                            "status": "SUSPICIOUS",
                            "is_simulation": True,
                            "timestamp": now,
                        }
                        for dp in chunk
                    ]
                    await _emit_packet_batch(pkts)
                    await _sleep(0.7)

            elif stage_key == "BRUTE_FORCE":
                # Port 22 only, ~25 SYN attempts sent across 5 batches
                attempts = max(int(effective_threshold * 1.5), 20)
                batch_count = 5
                per_batch = max(1, attempts // batch_count)
                for _ in range(batch_count):
                    if not _active:
                        cancelled = True
                        break
                    now = datetime.utcnow()
                    pkts = [
                        {
                            "src_ip": attacker_ip,
                            "dst_ip": target_ip,
                            "src_port": random.randint(1024, 65535),
                            "dst_port": 22,
                            "protocol": "TCP",
                            "packet_size": 128,
                            "flags": "S",
                            "status": "SUSPICIOUS",
                            "is_simulation": True,
                            "timestamp": now,
                        }
                        for _ in range(per_batch)
                    ]
                    await _emit_packet_batch(pkts)
                    await _sleep(0.8)

            elif stage_key == "SYN_FLOOD":
                # Burst of ~300 SYN packets sent over ~5s across 6 batches
                total_syns = max(int(effective_threshold * 1.5), 250)
                batches_count = 6
                per_batch = max(1, total_syns // batches_count)
                for _ in range(batches_count):
                    if not _active:
                        cancelled = True
                        break
                    now = datetime.utcnow()
                    pkts = [
                        {
                            "src_ip": attacker_ip,
                            "dst_ip": target_ip,
                            "src_port": random.randint(1024, 65535),
                            "dst_port": 80,
                            "protocol": "TCP",
                            "packet_size": 64,
                            "flags": "S",
                            "status": "SUSPICIOUS",
                            "is_simulation": True,
                            "timestamp": now,
                        }
                        for _ in range(per_batch)
                    ]
                    await _emit_packet_batch(pkts)
                    await _sleep(0.7)

            elif stage_key == "ICMP_FLOOD":
                # Burst of ~120 ICMP packets over ~5s across 6 batches
                total_icmp = max(int(effective_threshold * 1.5), 100)
                batches_count = 6
                per_batch = max(1, total_icmp // batches_count)
                for _ in range(batches_count):
                    if not _active:
                        cancelled = True
                        break
                    now = datetime.utcnow()
                    pkts = [
                        {
                            "src_ip": attacker_ip,
                            "dst_ip": target_ip,
                            "src_port": None,
                            "dst_port": None,
                            "protocol": "ICMP",
                            "packet_size": 64,
                            "flags": None,
                            "status": "SUSPICIOUS",
                            "is_simulation": True,
                            "timestamp": now,
                        }
                        for _ in range(per_batch)
                    ]
                    await _emit_packet_batch(pkts)
                    await _sleep(0.7)

            elif stage_key == "TRAFFIC_SPIKE":
                # Allow the global DoS-pattern alert cooldown from a previous
                # run or stage to expire so this stage can trigger a fresh alert.
                engine.clear_cooldowns({"MULTIPLE"})
                # Several attacker IPs sending a high rate at once.
                # Emit enough packets that the observed global PPS over the
                # 10s detection window exceeds baseline x multiplier x 2
                # (the documented dos_pattern rule) with ~50% margin.
                base_pps = traffic_processor.get_baseline_pps()
                required_global_pps = max(
                    150.0,
                    base_pps * settings.TRAFFIC_SPIKE_MULTIPLIER * 2.0 * 1.5,
                )
                spike_attackers = [attacker_ip] + [_generate_unique_attacker_ip() for _ in range(3)]
                batches_count = 7
                total_pkts = int(required_global_pps * 10)  # pps measured over a 10s window
                pkts_per_batch = max(30, total_pkts // batches_count)
                # Send ~70% of packets from the primary attacker so its per-IP
                # PPS also exceeds baseline x multiplier (unique attacker IP
                # per run), while the total volume trips the global rule too.
                for batch_idx in range(batches_count):
                    if not _active:
                        cancelled = True
                        break
                    now = datetime.utcnow()
                    primary_count = (pkts_per_batch * 7) // 10
                    batch_pkts = []
                    for i in range(pkts_per_batch):
                        pkt_ip = attacker_ip if i < primary_count else random.choice(spike_attackers)
                        batch_pkts.append({
                            "src_ip": pkt_ip,
                            "dst_ip": target_ip,
                            "src_port": random.randint(1024, 65535),
                            "dst_port": random.choice([80, 443, 8080]),
                            "protocol": random.choice(["TCP", "UDP"]),
                            "packet_size": 1200,
                            "flags": "PA",
                            "status": "SUSPICIOUS",
                            "is_simulation": True,
                            "timestamp": now,
                        })
                    await _emit_packet_batch(batch_pkts)
                    await _sleep(0.7)

            if cancelled:
                break

            # ── VERIFY DETECTION IN DATABASE ────────────────────────────────
            # Poll DB for up to ~6s (every 0.5s) for matching simulation alert
            poll_max_s = 6.0
            poll_interval_s = 0.5
            poll_steps = max(1, int(poll_max_s / poll_interval_s))

            detected = False
            matched_alert = None
            alert_latency_s = None

            expected_attack_types = [stage_key]
            if stage_key == "TRAFFIC_SPIKE":
                expected_attack_types = ["TRAFFIC_SPIKE", "DOS_PATTERN"]

            for _ in range(poll_steps):
                if not _active:
                    cancelled = True
                    break

                if _db_session_factory:
                    async with _db_session_factory() as db:
                        q = select(Alert).where(
                            Alert.is_simulation.is_(True),
                            Alert.attack_type.in_(expected_attack_types),
                            Alert.timestamp >= stage_start_time,
                        )
                        if stage_key != "TRAFFIC_SPIKE":
                            q = q.where(Alert.src_ip == attacker_ip)
                        else:
                            q = q.where((Alert.src_ip == attacker_ip) | (Alert.src_ip == "MULTIPLE"))

                        res = await db.execute(q.order_by(Alert.id.desc()))
                        matched_alert = res.scalars().first()
                        if matched_alert:
                            detected = True
                            alert_latency_s = round(max(0.1, (matched_alert.timestamp - stage_start_time).total_seconds()), 2)
                            break

                await _sleep(poll_interval_s)

            if detected and matched_alert:
                total_alerts_count += 1

            stage_res = {
                "run_id": run_id,
                "key": stage_key,
                "detected": detected,
                "skipped": False,
                "latency_s": alert_latency_s if detected else None,
                "alert_id": matched_alert.id if matched_alert else None,
                "attack_type": matched_alert.attack_type if matched_alert else stage_key,
                "src_ip": matched_alert.src_ip if matched_alert else attacker_ip,
            }
            results.append(stage_res)

            if _broadcast_callback:
                await _broadcast_callback("demo_stage_result", stage_res)

    except asyncio.CancelledError:
        logger.info(f"Guided scenario {run_id} cancelled.")
        cancelled = True
    except Exception as e:
        logger.error(f"Guided scenario error: {e}", exc_info=True)
    finally:
        _active = False
        _mode = "idle"
        _current_stage_key = None

        detected_count = sum(1 for r in results if r.get("detected"))
        attack_stages = sum(1 for r in results if not r.get("skipped", False))
        valid_latencies = [r["latency_s"] for r in results if r.get("detected") and r.get("latency_s") is not None]
        avg_latency_s = round(sum(valid_latencies) / len(valid_latencies), 2) if valid_latencies else 0.0

        finished_payload = {
            "run_id": run_id,
            "detected_count": detected_count,
            "attack_stages": attack_stages,
            "avg_latency_s": avg_latency_s,
            "total_alerts": total_alerts_count,
            "cancelled": cancelled,
        }

        if _broadcast_callback:
            await _broadcast_callback("demo_finished", finished_payload)

        logger.info(f"Guided scenario {run_id} finished: {finished_payload}")
        return finished_payload


def start(mode: str = "guided") -> dict:
    """Start either guided scenario or continuous background demo loop."""
    global _active, _mode, _task
    if _active:
        return {"status": "already_running", "mode": _mode, "run_id": _run_id}

    loop = asyncio.get_event_loop()
    if mode == "continuous":
        _active = True
        _mode = "continuous"
        _task = loop.create_task(_simulation_loop())
        logger.info("Continuous demo simulation started.")
        return {"status": "started", "mode": "continuous"}
    else:
        # Guided scenario
        _active = True
        _mode = "guided"
        _task = loop.create_task(run_guided_scenario())
        logger.info("Guided scenario orchestrator started.")
        return {"status": "started", "mode": "guided", "run_id": _run_id}


def stop():
    """Cancel the running task immediately and broadcast completion."""
    global _active, _mode, _task, _current_stage_key
    was_active = _active
    _active = False
    _mode = "idle"
    _current_stage_key = None
    if _task:
        _task.cancel()
        _task = None
    logger.info("Demo simulation stopped.")
    return {"status": "stopped", "was_active": was_active}


async def clear_simulation_data() -> dict:
    """Delete all simulation-only rows from DB and clear in-memory state."""
    counts = {"alerts": 0, "traffic": 0, "ip_stats": 0}
    if _db_session_factory:
        async with _db_session_factory() as db:
            # Delete simulation alerts
            del_alerts = await db.execute(delete(Alert).where(Alert.is_simulation.is_(True)))
            counts["alerts"] = del_alerts.rowcount or 0

            # Delete simulation traffic flows
            del_flows = await db.execute(delete(TrafficFlow).where(TrafficFlow.is_simulation.is_(True)))
            counts["traffic"] = del_flows.rowcount or 0

            # Delete IP statistics for simulated IPs
            sim_ips = list(traffic_processor.sim_ips)
            if sim_ips:
                del_ips = await db.execute(delete(IPStatistics).where(IPStatistics.ip.in_(sim_ips)))
                counts["ip_stats"] = del_ips.rowcount or 0

            await db.commit()

    # Clear in-memory processor simulation tracking
    engine.clear_cooldowns(traffic_processor.sim_ips)
    traffic_processor.sim_ips.clear()

    logger.info(f"Cleared simulation data: {counts}")
    return {"status": "cleared", "deleted": counts}


async def _simulation_loop():
    """Main continuous simulation loop — generates events every 1–2.5 seconds."""
    tick = 0
    while _active and _mode == "continuous":
        try:
            await _emit_traffic_batch(tick)
            if tick > 0 and tick % 6 == 0:
                await _maybe_inject_random_attack()
            tick += 1
            await asyncio.sleep(random.uniform(1.0, 2.5))
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Simulation loop error: {e}")
            await asyncio.sleep(2)


async def _emit_traffic_batch(tick: int):
    """Emit a batch of normal traffic packets into traffic_processor & DB."""
    if not _db_session_factory or not _broadcast_callback:
        return

    packets = []
    for _ in range(random.randint(3, 12)):
        src = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
        dst = random.choice(INTERNAL_IPS)
        proto = random.choice(PROTOCOLS)
        sport = random.randint(1024, 65535)
        dport = random.choice(COMMON_PORTS)
        size = random.randint(64, 1500)
        pkt = {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "packet_size": size,
            "flags": "PA" if proto == "TCP" else None,
            "status": "NORMAL",
            "is_simulation": True,
            "timestamp": datetime.utcnow(),
        }
        packets.append(pkt)
        await traffic_processor.process(pkt)

    async with _db_session_factory() as db:
        for p in packets:
            flow = TrafficFlow(**p)
            db.add(flow)
        await db.commit()

    if _broadcast_callback:
        await _broadcast_callback("traffic", {
            "packets": [
                {
                    "src_ip": p["src_ip"],
                    "dst_ip": p["dst_ip"],
                    "protocol": p["protocol"],
                    "src_port": p["src_port"],
                    "dst_port": p["dst_port"],
                    "packet_size": p["packet_size"],
                    "status": "NORMAL",
                    "timestamp": p["timestamp"].isoformat(),
                    "is_simulation": True,
                }
                for p in packets
            ],
            "pps": len(packets),
        })


async def inject_attack_packets(attack_type: str, attacker_ip: Optional[str] = None):
    """Inject a burst of attack traffic into traffic_processor to trigger real-time IDS engine."""
    if not attacker_ip:
        attacker_ip = _generate_unique_attacker_ip()
    target_ip = random.choice(INTERNAL_IPS)
    attack_upper = attack_type.upper()

    packets = []
    now = datetime.utcnow()

    if attack_upper == "PORT_SCAN":
        target_ports = random.sample(range(1000, 9000), 25)
        for dport in target_ports:
            packets.append({
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": dport,
                "protocol": "TCP",
                "packet_size": random.randint(64, 128),
                "flags": "S",
                "status": "SUSPICIOUS",
                "is_simulation": True,
                "timestamp": now,
            })
    elif attack_upper == "BRUTE_FORCE":
        for _ in range(15):
            packets.append({
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": 22,
                "protocol": "TCP",
                "packet_size": random.randint(64, 256),
                "flags": "S",
                "status": "SUSPICIOUS",
                "is_simulation": True,
                "timestamp": now,
            })
    elif attack_upper == "SYN_FLOOD":
        for _ in range(120):
            packets.append({
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": 80,
                "protocol": "TCP",
                "packet_size": 64,
                "flags": "S",
                "status": "SUSPICIOUS",
                "is_simulation": True,
                "timestamp": now,
            })
    elif attack_upper == "ICMP_FLOOD":
        for _ in range(60):
            packets.append({
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": None,
                "dst_port": None,
                "protocol": "ICMP",
                "packet_size": 64,
                "flags": None,
                "status": "SUSPICIOUS",
                "is_simulation": True,
                "timestamp": now,
            })
    elif attack_upper in ("TRAFFIC_SPIKE", "DOS"):
        for _ in range(250):
            packets.append({
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 53]),
                "protocol": random.choice(["TCP", "UDP"]),
                "packet_size": 1400,
                "flags": "PA",
                "status": "SUSPICIOUS",
                "is_simulation": True,
                "timestamp": now,
            })

    await _emit_packet_batch(packets)
    logger.info(f"Injected {len(packets)} attack packets for scenario {attack_upper} from {attacker_ip}")
    return {"attack_type": attack_upper, "attacker_ip": attacker_ip, "packets_injected": len(packets)}


async def _maybe_inject_random_attack():
    scenario = random.choice(["PORT_SCAN", "BRUTE_FORCE", "SYN_FLOOD", "ICMP_FLOOD"])
    await inject_attack_packets(scenario)
