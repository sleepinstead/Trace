"""Trace API."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import database
from .config import get_settings
from .intel.providers import provider_status
from .ml.predictor import classifier
from .routers import scans, threats

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    database.init_db()
    classifier.load(train_if_missing=True)
    yield


app = FastAPI(
    title="Trace API",
    version="1.0.0",
    description="Phishing detection for URLs, domains and email messages.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(scans.router)
app.include_router(threats.router)


@app.get("/api/health", tags=["system"])
def health() -> dict:
    return {"status": "ok", "model_loaded": classifier.ready}


@app.get("/api/intel/status", tags=["system"])
def intel_status() -> list[dict]:
    return provider_status()


@app.get("/api/model", tags=["system"])
def model_info() -> dict:
    return classifier.info()
