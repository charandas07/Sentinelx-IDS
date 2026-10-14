"""Demo Mode API endpoints."""
from typing import Optional
from fastapi import APIRouter, Query
from app.services import demo_simulator

router = APIRouter(prefix="/api/demo", tags=["demo"])


@router.post("/start")
async def start_demo(mode: str = Query("guided", regex="^(guided|continuous)$")):
    res = demo_simulator.start(mode=mode)
    return {
        "status": res.get("status", "started"),
        "mode": res.get("mode", mode),
        "run_id": res.get("run_id"),
        "message": f"Demo simulation mode '{mode}' activated. All events are labeled as SIMULATION.",
    }


@router.post("/stop")
async def stop_demo():
    res = demo_simulator.stop()
    return {"status": "stopped", "message": "Demo simulation stopped.", "details": res}


@router.get("/status")
async def demo_status():
    return demo_simulator.get_status()


@router.delete("/data")
async def delete_demo_data():
    res = await demo_simulator.clear_simulation_data()
    return {
        "status": "success",
        "message": "Deleted simulated traffic flows, alerts, and IP statistics.",
        "details": res,
    }


@router.post("/attack/{attack_type}")
async def trigger_attack(attack_type: str, src_ip: Optional[str] = Query(None)):
    res = await demo_simulator.inject_attack_packets(attack_type, attacker_ip=src_ip)
    return {
        "status": "success",
        "message": f"Injected {attack_type.upper()} attack packets into real-time IDS pipeline.",
        "details": res,
    }
