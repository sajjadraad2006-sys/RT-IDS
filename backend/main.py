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
from .api import auth, chat, decision, detection, events, mitre, operations, settings, simulation, universal_ingest
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
    import os
    if os.getenv("CG_EAGER_LOAD_PIPELINE", "false").lower() in ("true", "1", "yes"):
        detection.eager_load_pipeline()

    from .detection.live_worker import default_live_worker
    from .detection.live_sniffer import default_live_sniffer

    default_live_sniffer.on_flow_flushed = default_live_worker.enqueue_flow
    default_live_worker.set_pipeline_getter(detection._get_pipeline)

    if os.getenv("CG_AUTOSTART_LIVE_WORKER", "false").lower() in ("true", "1", "yes"):
        default_live_worker.start()
        capture_ok = default_live_sniffer.start_capture()
        if not capture_ok:
            import logging
            logging.getLogger("cyberguard.main").warning(
                "Autostart live sniffer could not bind raw socket (requires administrator/root elevation). "
                "Flow worker is active; run CyberGuard as Administrator to enable promiscuous raw capture."
            )

    from .actuators.router import default_router
    try:
        default_router.sweep_expired_actions()
        default_router.start_ttl_reaper()
    except Exception as reaper_err:
        logging.getLogger("cyberguard.main").error("Failed to start TTL reaper or sweep expired actions: %s", reaper_err, exc_info=True)

    # Automatically ensure local LLM engine (Foundation-Sec-8B on RTX 5050) is running
    try:
        from .llm.manager import ensure_local_llm
        ensure_local_llm(background=True)
    except Exception as llm_init_err:
        logging.getLogger("cyberguard.main").warning("Local LLM auto-startup check: %s", llm_init_err)

    yield

    default_router.stop_ttl_reaper()
    default_live_sniffer.stop_capture()
    if default_live_worker.get_status()["is_running"]:
        default_live_worker.stop(drain=True)
    else:
        default_live_worker._drain_remaining()



from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from .limiter import limiter

app = FastAPI(
    title="CyberGuard",
    version="2.0.0",
    description=(
        "Autonomous Real-Time Intrusion Detection & Active Cyber Defense System (RT-IDS). "
        "Pipeline v2 executes high-throughput ML inference (mean 2.3ms/flow, p99 3.7ms) with "
        "sliding-window multi-target scan correlation, live raw-packet sniffing (AF_PACKET / WinRaw), "
        "and guarded autonomous containment actuators with cryptographic HMAC-SHA256 rollback receipts."
    ),
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

app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(decision.router)
app.include_router(detection.router)
app.include_router(events.router)
app.include_router(mitre.router)
app.include_router(operations.router)
app.include_router(settings.router)
app.include_router(simulation.router)
app.include_router(universal_ingest.router)


FRONTEND = BASE_DIR / "frontend"


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(
        FRONTEND / "index.html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# Serve static files (CSS, JS)
if FRONTEND.exists():
    app.mount("/css", StaticFiles(directory=FRONTEND / "css"), name="css")
    app.mount("/js", StaticFiles(directory=FRONTEND / "js"), name="js")
    app.mount("/assets", StaticFiles(directory=FRONTEND / "assets"), name="assets") if (FRONTEND / "assets").exists() else None
