"""CyberGuard — FastAPI entry point.
Serves the SPA frontend + all API routers. Local-first: binds to 127.0.0.1.

    uvicorn backend.main:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from .db.init_db import init_all
from .api import chat, decision, detection, mitre, settings
from .config import ALLOWED_HOSTS, ALLOWED_ORIGINS, BASE_DIR, LOG_LEVEL
from .security import ApiAccessMiddleware, RequestLimitsMiddleware, SecurityHeadersMiddleware

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S"
)

@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_all()
    yield


from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from .limiter import limiter

app = FastAPI(
    title="CyberGuard",
    version="2.0.0",
    description="Multi-layer AI cyber threat detection — "
                "4-stage pipeline first, LLM explains. "
                "Built on CICIDS2017, MITRE ATT&CK, XGBoost, deep autoencoder.",
    lifespan=_lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ApiAccessMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
app.add_middleware(RequestLimitsMiddleware)

# Local UI only; tighten origins if you ever expose this beyond localhost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-CyberGuard-Token"]
)

app.include_router(chat.router)
app.include_router(decision.router)
app.include_router(detection.router)
app.include_router(mitre.router)
app.include_router(settings.router)


FRONTEND = BASE_DIR / "frontend"


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


# Serve static files (CSS, JS)
if FRONTEND.exists():
    app.mount("/css", StaticFiles(directory=FRONTEND / "css"), name="css")
    app.mount("/js", StaticFiles(directory=FRONTEND / "js"), name="js")
    app.mount("/assets", StaticFiles(directory=FRONTEND / "assets"), name="assets") if (FRONTEND / "assets").exists() else None
