from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile

from .. import database
from ..analyzers.email_scan import scan_email
from ..analyzers.scan import scan_domain, scan_url
from ..core.urltools import InvalidURL
from ..schemas import DomainScanRequest, EmailScanRequest, ScanList, ScanResult, UrlScanRequest

router = APIRouter(prefix="/api", tags=["scans"])

MAX_EML_BYTES = 5_000_000


@router.post("/scan/url", response_model=ScanResult)
async def post_url_scan(req: UrlScanRequest) -> dict:
    try:
        result = await scan_url(req.url, deep=req.deep, use_intel=req.use_intel)
    except InvalidURL as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    database.save_scan(result)
    return result


@router.post("/scan/domain", response_model=ScanResult)
async def post_domain_scan(req: DomainScanRequest) -> dict:
    try:
        result = await scan_domain(req.domain, use_intel=req.use_intel)
    except InvalidURL as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    database.save_scan(result)
    return result


@router.post("/scan/email", response_model=ScanResult)
async def post_email_scan(req: EmailScanRequest) -> dict:
    if not (req.raw or req.body or req.sender or req.subject):
        raise HTTPException(status_code=422, detail="Provide the raw message or at least a sender, subject or body")
    result = await scan_email(req.raw, sender=req.sender, subject=req.subject, body=req.body,
                              deep=req.deep, use_intel=req.use_intel)
    database.save_scan(result)
    return result


@router.post("/scan/email/upload", response_model=ScanResult)
async def post_email_upload(
    file: UploadFile = File(..., description=".eml file"),
    deep: bool = Form(True),
    use_intel: bool = Form(True),
) -> dict:
    data = await file.read(MAX_EML_BYTES + 1)
    if len(data) > MAX_EML_BYTES:
        raise HTTPException(status_code=413, detail="Message too large (5 MB max)")
    raw = data.decode("utf-8", errors="replace")
    result = await scan_email(raw, deep=deep, use_intel=use_intel)
    database.save_scan(result)
    return result


@router.get("/scans", response_model=ScanList)
def get_scans(
    scan_type: Literal["url", "domain", "email"] | None = None,
    verdict: Literal["safe", "suspicious", "malicious"] | None = None,
    q: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict:
    items, total = database.list_scans(scan_type=scan_type, verdict=verdict, query=q, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/scans/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str) -> dict:
    result = database.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str) -> None:
    if not database.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/stats")
def get_stats(days: int = Query(30, ge=7, le=365)) -> dict:
    return database.scan_stats(days)
