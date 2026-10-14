"""
SentinelX FastAPI Application
Main entry point: sets up CORS, routers, lifespan, WebSocket broadcaster,
and background real-time intrusion detection loop.
"""
import asyncio
import hmac
import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status as http_status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import settings
from app.database import init_db, AsyncSessionLocal
from app.services.seed import seed_rules
from app.services import demo_simulator, capture
from app.services.traffic_processor import traffic_processor
from app.api import alerts, status, traffic, ip_analysis, rules, pcap, demo, reports, whitelist, capture_ctrl, flows, incidents

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)

if not settings.DEBUG and settings.SECRET_KEY == "sentinelx-dev-secret-change-in-production":
    raise ValueError("Must change SECRET_KEY in production when DEBUG=false")

security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != settings.SECRET_KEY:
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials

# ── WebSocket Connection Manager ──────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._connections: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.add(ws)
        logger.info(f"WebSocket client connected. Total: {len(self._connections)}")

    def disconnect(self, ws: WebSocket):
        self._connections.discard(ws)
        logger.info(f"WebSocket client disconnected. Total: {len(self._connections)}")

    async def broadcast(self, message: dict):
        dead = set()
        payload = json.dumps(message)
        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._connections.discard(ws)

    def count(self) -> int:
        return len(self._connections)


manager = ConnectionManager()


async def broadcast_callback(msg_type: str, data: dict):
    await manager.broadcast({"type": msg_type, "data": data})


# ── Background Tasks ──────────────────────────────────────────────────────────

async def _stats_broadcaster():
    """Broadcast live stats every 2 seconds."""
    while True:
        await asyncio.sleep(2)
        try:
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select, func
                from app.models.alert import Alert
                from app.models.ip_stats import IPStatistics

                total_pkts = traffic_processor.get_total_packets()
                total_bytes = traffic_processor.get_total_bytes()
                total_alerts = await db.scalar(select(func.count(Alert.id))) or 0
                critical = await db.scalar(
                    select(func.count(Alert.id)).where(Alert.severity == "CRITICAL")
                ) or 0
                suspicious = await db.scalar(
                    select(func.count(IPStatistics.id)).where(IPStatistics.threat_score > 40)
                ) or 0

                history = traffic_processor.get_pps_history(60)
                current_pps = history[-1]["pps"] if history else 0.0

                stats_dict = capture.get_stats()
                from app.services.flow_tracker import flow_tracker
                flow_stats = flow_tracker.stats()
                await broadcast_callback("stats", {
                    "packets_analyzed": total_pkts,
                    "threats_detected": total_alerts,
                    "critical_alerts": critical,
                    "suspicious_ips": suspicious,
                    "traffic_bytes": total_bytes,
                    "is_capturing": capture.is_capturing(),
                    "capture_error": capture.get_last_error(),
                    "active_iface": stats_dict.get("active_iface"),
                    "demo_mode": demo_simulator.is_active(),
                    "current_pps": current_pps,
                    "pps_history": history[-30:],
                    "active_flows": flow_stats.get("active_flows", 0),
                })
        except Exception as e:
            logger.error(f"Stats broadcast error: {e}")


async def _traffic_pps_sampler():
    """Sample packets-per-second every second."""
    prev_total = 0
    prev_inbound = 0
    while True:
        await asyncio.sleep(1)
        cur_total = traffic_processor.get_total_packets()
        total_pps = cur_total - prev_total
        prev_total = cur_total
        traffic_processor.sample_global_pps(float(total_pps))

        cur_inbound = traffic_processor.get_inbound_packets()
        inbound_pps = cur_inbound - prev_inbound
        prev_inbound = cur_inbound
        traffic_processor.sample_inbound_pps(float(inbound_pps))


async def _intrusion_detection_loop():
    """Run rule-based IDS detection engine across traffic processor counters every 1.5 seconds."""
    from app.detection.engine import run_detection
    while True:
        await asyncio.sleep(1.5)
        try:
            async with AsyncSessionLocal() as db:
                await run_detection(
                    db,
                    traffic_processor,
                    is_simulation=demo_simulator.is_active(),
                    broadcast_callback=broadcast_callback,
                )
        except Exception as e:
            logger.error(f"Intrusion detection loop error: {e}")


async def _packet_ingestion_loop():
    """Drain captured packets from Scapy capture thread and ingest into traffic_processor & DB."""
    from app.models.traffic import TrafficFlow
    while True:
        await asyncio.sleep(0.5)
        try:
            raw_packets = capture.drain_queue()
            if not raw_packets:
                continue

            for pkt in raw_packets:
                await traffic_processor.process(pkt)

            async with AsyncSessionLocal() as db:
                flows_to_insert = []
                for pkt in raw_packets:
                    is_suspicious = pkt.get("status") != "NORMAL" or pkt.get("flags") in ("S",)
                    # Sample 10% of normal packets to save DB space
                    import random
                    if is_suspicious or random.random() < 0.1:
                        flows_to_insert.append(TrafficFlow(
                            src_ip=pkt.get("src_ip"),
                            dst_ip=pkt.get("dst_ip"),
                            src_port=pkt.get("src_port"),
                            dst_port=pkt.get("dst_port"),
                            protocol=pkt.get("protocol", "OTHER"),
                            packet_size=pkt.get("packet_size", 0),
                            flags=pkt.get("flags"),
                            status=pkt.get("status", "NORMAL"),
                            is_simulation=pkt.get("is_simulation", False),
                            timestamp=pkt.get("timestamp"),
                        ))
                if flows_to_insert:
                    db.add_all(flows_to_insert)
                    await db.commit()

            await broadcast_callback("traffic", {
                "packets": [
                    {
                        "src_ip": p["src_ip"],
                        "dst_ip": p["dst_ip"],
                        "protocol": p["protocol"],
                        "src_port": p["src_port"],
                        "dst_port": p["dst_port"],
                        "packet_size": p["packet_size"],
                        "status": p.get("status", "NORMAL"),
                        "timestamp": p["timestamp"].isoformat() if hasattr(p["timestamp"], "isoformat") else str(p["timestamp"]),
                        "is_simulation": p.get("is_simulation", False),
                    }
                    for p in raw_packets[:10]
                ],
                "pps": len(raw_packets),
            })
        except Exception as e:
            logger.error(f"Packet ingestion loop error: {e}")


async def _flow_sweep_task():
    """Periodically expire idle/active flows so memory stays bounded."""
    from app.services.flow_tracker import flow_tracker
    while True:
        await asyncio.sleep(15)
        try:
            expired = flow_tracker.sweep()
            if expired:
                logger.debug(f"Flow sweep expired {expired} flows")
        except Exception as e:
            logger.error(f"Flow sweep error: {e}")


async def _data_retention_task():
    """Background task to delete old TrafficFlow rows."""
    while True:
        try:
            async with AsyncSessionLocal() as db:
                from app.models.traffic import TrafficFlow
                from sqlalchemy import delete
                import datetime
                cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=settings.RETENTION_HOURS)
                await db.execute(delete(TrafficFlow).where(TrafficFlow.timestamp < cutoff))
                await db.commit()
        except Exception as e:
            logger.error(f"Data retention loop error: {e}")
        # Run once every hour
        await asyncio.sleep(3600)

# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SentinelX starting up…")
    await init_db()
    async with AsyncSessionLocal() as db:
        await seed_rules(db)
        from sqlalchemy import select
        from app.models.whitelist import WhitelistEntry
        wl_result = await db.execute(select(WhitelistEntry.ip))
        for ip in wl_result.scalars().all():
            traffic_processor._whitelist_ips.add(ip)

    # Wire demo simulator
    demo_simulator.set_broadcast_callback(broadcast_callback)
    demo_simulator.set_db_factory(AsyncSessionLocal)

    # Attempt live packet capture start
    capture_started = capture.start_capture(iface=settings.CAPTURE_IFACE, bpf_filter=settings.CAPTURE_FILTER)
    logger.info(f"Live Scapy packet capture active: {capture_started}")

    # Also start simulation traffic generator to ensure steady continuous packet stream
    if settings.ENABLE_DEMO_ON_STARTUP:
        demo_simulator.start()

    # Start background tasks
    tasks = [
        asyncio.create_task(_stats_broadcaster()),
        asyncio.create_task(_traffic_pps_sampler()),
        asyncio.create_task(_intrusion_detection_loop()),
        asyncio.create_task(_packet_ingestion_loop()),
        asyncio.create_task(_data_retention_task()),
        asyncio.create_task(_flow_sweep_task()),
    ]

    logger.info("SentinelX IDS Engine is ONLINE and monitoring traffic for real-time intrusions.")
    yield

    # Shutdown
    demo_simulator.stop()
    capture.stop_capture()
    for t in tasks:
        t.cancel()
    # Release flow-tracking resources.
    try:
        from app.services.flow_tracker import flow_tracker
        flow_tracker.clear()
    except Exception:
        pass
    logger.info("SentinelX shutting down.")


# ── App Setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SentinelX IDS API",
    description="Network-Flow-Aware Intrusion Detection & Evidence-Based Attack Investigation – REST API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
api_dependencies = [Depends(verify_token)]
app.include_router(status.router, dependencies=api_dependencies)
app.include_router(alerts.router, dependencies=api_dependencies)
app.include_router(traffic.router, dependencies=api_dependencies)
app.include_router(ip_analysis.router, dependencies=api_dependencies)
app.include_router(rules.router, dependencies=api_dependencies)
app.include_router(pcap.router, dependencies=api_dependencies)
app.include_router(demo.router, dependencies=api_dependencies)
app.include_router(reports.router, dependencies=api_dependencies)
app.include_router(whitelist.router, dependencies=api_dependencies)
app.include_router(capture_ctrl.router, dependencies=api_dependencies)
app.include_router(flows.router, dependencies=api_dependencies)
app.include_router(incidents.router, dependencies=api_dependencies)


# ── Auth Endpoint ─────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/login")
async def login(body: LoginRequest):
    if not settings.ADMIN_PASSWORD:
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Admin password is not configured",
        )
    user_ok = hmac.compare_digest(body.username, settings.ADMIN_USER)
    pass_ok = hmac.compare_digest(body.password, settings.ADMIN_PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    return {"token": settings.SECRET_KEY}


# ── WebSocket Endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if token != settings.SECRET_KEY:
        await websocket.close(code=1008)
        return
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket error: {e}")
        manager.disconnect(websocket)


@app.get("/")
async def root():
    return {"message": "SentinelX IDS API", "version": "2.0.0", "docs": "/docs"}
