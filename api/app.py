"""
FastAPI API for CyberSentinel Web API(DB-backed, import-based).
Run:
  uvicorn api.app:app --reload --port 8001
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Database
from api.database import engine
from api.models import Base

# Routes
from api.routes import import_report, scans

app = FastAPI(title="CyberSentinel Web API", version="1.0")

# ---------------- DATABASE INIT ----------------
Base.metadata.create_all(bind=engine)

# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- STATIC (OPTIONAL) ----------------
# Only needed if you want to serve HTML reports
app.mount("/static", StaticFiles(directory="reports"), name="static")

# ---------------- ROUTES ----------------
app.include_router(import_report.router)
app.include_router(scans.router)

# ---------------- HEALTH / ROOT ----------------
@app.get("/")
def root():
    return {
        "message": "CyberSentinel Web API is running",
        "docs": "/docs",
        "endpoints": [
            "/health",
            "/import_report",
            "/scans",
            "/scans/{scan_id}/findings"
        ]
    }

@app.get("/health")
def health():
    return {"status": "ok"}
