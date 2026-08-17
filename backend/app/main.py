import os
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.alerts import router as alerts_router
from app.api.v1.auth import router as auth_router
from app.api.v1.detection_router import router as detection_router
from app.api.v1.events import router as events_router
from app.api.v1.health import router as health_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.ingest import router as ingest_router
from app.api.v1.machines import router as machines_router
from app.api.v1.rules import router as rules_router
from app.api.v1.stats import router as stats_router
from app.core.config import settings
from app.core.exceptions import (
    SecOpsException,
    global_exception_handler,
    secops_exception_handler,
    validation_exception_handler,
)
from app.core.logging import setup_logging
from app.db.session import Base, SessionLocal, engine
from app.detection.rules.registry import registry
from app.services.user_service import UserService

setup_logging()

# Ensure DB tables exist on startup
Base.metadata.create_all(bind=engine)

# Seed rules and default users into database
with SessionLocal() as db_session:
    registry.seed_rules(db_session)
    UserService.seed_default_users(db_session)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
origins = settings.ALLOWED_ORIGINS
if isinstance(origins, str):
    origins = [origins]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next: Callable[[Request], Any]) -> Response:
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Exception handlers
app.add_exception_handler(SecOpsException, secops_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, global_exception_handler)

# Include API v1 Routers under /api/v1
api_v1_prefix = settings.API_V1_STR

app.include_router(health_router, prefix=api_v1_prefix)
app.include_router(ingest_router, prefix=api_v1_prefix)
app.include_router(events_router, prefix=api_v1_prefix)
app.include_router(machines_router, prefix=api_v1_prefix)
app.include_router(rules_router, prefix=api_v1_prefix)
app.include_router(incidents_router, prefix=api_v1_prefix)
app.include_router(detection_router, prefix=api_v1_prefix)
app.include_router(stats_router, prefix=api_v1_prefix)
app.include_router(alerts_router, prefix=api_v1_prefix)
app.include_router(auth_router, prefix=api_v1_prefix)

# Static Files Directory
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=FileResponse)
def serve_dashboard():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"project": settings.PROJECT_NAME, "version": settings.VERSION, "docs": "/docs"}


@app.get("/dashboard", response_class=FileResponse)
def serve_dashboard_alias():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"project": settings.PROJECT_NAME, "version": settings.VERSION, "docs": "/docs"}


@app.get("/api/info")
def api_info():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "api_v1": settings.API_V1_STR
    }
