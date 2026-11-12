from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from .. import database
from ..analyzers.scan import normalize_domain
from ..core.urltools import InvalidURL, parse_url
from ..schemas import ThreatList, ThreatRecord, ThreatRecordIn

router = APIRouter(prefix="/api/threats", tags=["threat records"])


def _normalize(indicator: str, kind: str) -> str:
    value = indicator.strip()
    if kind == "url":
        return parse_url(value).url
    if kind == "domain":
        return normalize_domain(value)
    return value.lower()


@router.get("", response_model=ThreatList)
def list_threats(q: str | None = Query(None, max_length=200), limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0)) -> dict:
    items, total = database.list_threats(q, limit, offset)
    return {"items": items, "total": total}


@router.post("", response_model=ThreatRecord, status_code=201)
def add_threat(record: ThreatRecordIn) -> dict:
    try:
        indicator = _normalize(record.indicator, record.indicator_type)
    except InvalidURL as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return database.add_threat(indicator, record.indicator_type, record.threat_type, "manual", record.description)


@router.delete("/{threat_id}", status_code=204)
def delete_threat(threat_id: int) -> None:
    if not database.delete_threat(threat_id):
        raise HTTPException(status_code=404, detail="Record not found")
