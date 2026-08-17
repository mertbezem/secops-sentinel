import os
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
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

# Sunucu başlangıcında veritabanı tablolarının varlığını doğrula
Base.metadata.create_all(bind=engine)

# Varsayılan kuralları ve kullanıcı hesaplarını tohumla (seed)
with SessionLocal() as db_session:
    registry.seed_rules(db_session)
    UserService.seed_default_users(db_session)

openapi_tags = [
    {
        "name": "Auth",
        "description": "🔐 **JWT Kimlik Doğrulama & RBAC** — Kullanıcı girişi, rol tabanlı erişim kontrolü (`ADMIN`, `ANALYST`, `VIEWER`) ve kullanıcı yönetimi.",
    },
    {
        "name": "Detection",
        "description": "⚡ **Otonom Algılama Motoru** — R001–R005 tespit kurallarını çalıştırır, anomalileri yakalar ve olay korelasyonu üretir.",
    },
    {
        "name": "Incidents",
        "description": "🚨 **Güvenlik Olayları & Adli Analiz (SOC)** — Olay yaşam döngüsü, yapay zeka (AI) kök neden analizi, adli PDF raporlama ve denetim notları.",
    },
    {
        "name": "Events",
        "description": "📜 **Ham Log & Olay Arama Gezgini** — Normalleştirilmiş Windows Event Log kayıtlarını filtreleme, arama ve sayfalandırma.",
    },
    {
        "name": "Machines",
        "description": "🖥️ **Uç Nokta Varlık & Zaman Çizelgesi** — Sunucu kritiklik seviyeleri, geçmiş telemetri ve olay zaman çizelgeleri.",
    },
    {
        "name": "Rules",
        "description": "⚙️ **Algılama Kuralları Yönetimi** — Kural parametrelerini (Eşik, Zaman Penceresi, Ağırlık) çalışma anında dinamik olarak güncelleme.",
    },
    {
        "name": "Stats",
        "description": "📊 **SOC İstatistikleri & MITRE ATT&CK** — Genel tehdit metrikleri, zaman serisi dağılımı ve taktiksel ısı haritası.",
    },
    {
        "name": "Alerts",
        "description": "🔔 **Alarm & Webhook Entegrasyonu** — E-posta ve webhook bildirim ayarları, otomatik alarm tetikleme.",
    },
    {
        "name": "Ingest",
        "description": "📥 **Toplu Log Yükleme & Ayrıştırma** — CSV dosyalarını yükleme, normalizasyon ve şablonlama arka plan işleri.",
    },
    {
        "name": "Health",
        "description": "❤️ **Sistem Sağlık Durumu** — API ve veritabanı liveness/readiness kontrolleri.",
    },
]

app_description = """
### 🛡️ Kurumsal Seviye SIEM & Olay Müdahale REST API Platformu

**SecOps Sentinel API**; ham Windows Olay Günlüklerinin (Event Log) normalizasyonunu, şablonlamasını,
davranışsal taban çizgisi analizini, MITRE ATT&CK eşleştirmesini, heuristik risk skorlamasını ve
otonom olay korelasyonunu sağlayan yüksek performanslı bir güvenlik servisidir.

#### 🔐 Kimlik Doğrulama Bilgisi:
* Sistem **JWT Bearer Token** standardı ile korunmaktadır.
* Token almak için `/api/v1/auth/login` uç noktasına kullanıcı adı ve şifrenizi gönderin.
* Yetki seviyeleri: **ADMIN** (Tam Yetki), **ANALYST** (Analiz & Güncelleme), **VIEWER** (Salt Okunur).
"""

app = FastAPI(
    title="SecOps Sentinel — SOC & SIEM API",
    description=app_description,
    version=settings.VERSION,
    openapi_tags=openapi_tags,
    openapi_url="/openapi.json",
    docs_url=None,  # Custom modern Swagger UI rendered below
    redoc_url=None  # Custom ReDoc rendered below
)

# CORS (Cross-Origin Resource Sharing) yapılandırması
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


# Global hata yakalayıcıları (Exception Handlers)
app.add_exception_handler(SecOpsException, secops_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, global_exception_handler)

# API v1 rotalarını /api/v1 altına dahil et
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

# Statik dosya dizini (Web Arayüzü ve CSS)
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="SecOps Sentinel — API Dokümantasyonu & Swagger",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
        swagger_css_url="/static/swagger_theme.css",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
    )


@app.get("/redoc", include_in_schema=False)
async def custom_redoc_html():
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="SecOps Sentinel — ReDoc API Dokümantasyonu",
        redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )


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
