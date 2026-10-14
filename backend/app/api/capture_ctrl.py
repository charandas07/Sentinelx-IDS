"""Capture Control API.
GET  /api/capture/interfaces  — list available network interfaces
POST /api/capture/start       — start capture (optional iface body)
POST /api/capture/stop        — stop capture
"""
from typing import List, Optional
from fastapi import APIRouter
from pydantic import BaseModel

from app.services import capture
from app.config import settings

router = APIRouter(prefix="/api/capture", tags=["capture"])


class CaptureStartRequest(BaseModel):
    iface: Optional[str] = None


class CaptureStatusResponse(BaseModel):
    is_capturing: bool
    active_iface: Optional[str]
    capture_error: Optional[str]
    packets_captured: int
    dropped_packets: int


@router.get("/interfaces", response_model=List[str])
async def list_interfaces():
    """Return list of available network interface names."""
    return capture.list_interfaces()


@router.post("/start", response_model=CaptureStatusResponse)
async def start_capture(body: CaptureStartRequest = CaptureStartRequest()):
    iface = body.iface or settings.CAPTURE_IFACE or None
    capture.start_capture(iface=iface, bpf_filter=settings.CAPTURE_FILTER)
    stats = capture.get_stats()
    return CaptureStatusResponse(
        is_capturing=capture.is_capturing(),
        active_iface=stats.get("active_iface"),
        capture_error=stats.get("capture_error"),
        packets_captured=stats.get("packets_captured", 0),
        dropped_packets=stats.get("dropped_packets", 0),
    )


@router.post("/stop", response_model=CaptureStatusResponse)
async def stop_capture():
    capture.stop_capture()
    stats = capture.get_stats()
    return CaptureStatusResponse(
        is_capturing=capture.is_capturing(),
        active_iface=stats.get("active_iface"),
        capture_error=stats.get("capture_error"),
        packets_captured=stats.get("packets_captured", 0),
        dropped_packets=stats.get("dropped_packets", 0),
    )
