"""PCAP Analyzer API endpoint."""
import os
import time
import logging
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config import settings
from app.services.pcap_analyzer import analyze_pcap
from app.schemas import PCAPReport

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/pcap", tags=["pcap"])

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_DIR = "data/pcaps"


@router.post("/upload", response_model=PCAPReport)
async def upload_pcap(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    # Validate extension
    _, ext = os.path.splitext(file.filename or "")
    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")

    # Read and size-check
    content = await file.read()
    max_bytes = settings.MAX_PCAP_SIZE_MB * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.MAX_PCAP_SIZE_MB} MB limit")

    # Save to disk
    os.makedirs(PCAP_DIR, exist_ok=True)
    safe_name = f"{int(time.time())}_{os.path.basename(file.filename or 'upload.pcap')}"
    save_path = os.path.join(PCAP_DIR, safe_name)
    with open(save_path, "wb") as f:
        f.write(content)

    logger.info(f"PCAP uploaded: {safe_name} ({len(content)} bytes)")

    try:
        report = await analyze_pcap(save_path, db)
        return report
    except Exception as e:
        logger.error(f"PCAP analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
