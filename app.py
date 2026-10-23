"""
ADX Group (adxgroup.tech) — Main FastAPI Application Controller.
Wraps FastAPI with a2wsgi for seamless compatibility on Azure App Service (Gunicorn WSGI)
and local Uvicorn ASGI execution.
"""

from pathlib import Path
from typing import Optional

from a2wsgi import ASGIMiddleware
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from core.ai_engine import ask_adx_ai_consultant, generate_ai_executive_summary
from core.notifier import record_client_lead
from core.scanner import run_full_diagnostic

BASE_DIR = Path(__file__).resolve().parent

asgi_app = FastAPI(
    title="ADX Group — Enterprise AI, Cloud & Cyber Systems",
    description="Official portal and 5-vector diagnostic engine for ADX Group (adxgroup.tech)",
    version="2.0.0",
)

STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

asgi_app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


class ScanRequest(BaseModel):
    domain: str


class ChatRequest(BaseModel):
    message: str


class LeadRequest(BaseModel):
    company_or_name: str
    email: str
    division: Optional[str] = "ADX Cyber — Security Audit"
    domain: Optional[str] = ""
    message: Optional[str] = ""


@asgi_app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the main ADX Group Enterprise Portal."""
    return templates.TemplateResponse(request=request, name="index.html")


@asgi_app.get("/api/health")
async def health_check():
    """Health check endpoint for uptime monitoring and cloud readiness."""
    return {
        "status": "ONLINE",
        "entity": "ADX Group (adxgroup.tech)",
        "divisions": ["ADX Cyber", "ADX Cloud & Systems", "ADX Intelligence"],
        "contact": "contact@adxgroup.tech",
    }


@asgi_app.post("/api/scan")
async def api_scan_domain(payload: ScanRequest):
    """Run the 5-vector passive security & infrastructure diagnostic on a target domain."""
    try:
        scan_data = await run_full_diagnostic(payload.domain)
        scan_data["ai_executive_summary"] = generate_ai_executive_summary(scan_data)
        return JSONResponse(content={"ok": True, "data": scan_data})
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Diagnostic engine encountered an error: {str(exc)[:120]}",
        )


@asgi_app.post("/api/chat")
async def api_ai_consultant(payload: ChatRequest):
    """Interact with the 24/7 ADX AI Systems Consultant (protected by Gate 3 prompt guard)."""
    result = await ask_adx_ai_consultant(payload.message)
    return JSONResponse(content={"ok": True, "data": result})


@asgi_app.post("/api/lead")
async def api_submit_lead(payload: LeadRequest):
    """Submit a client consultation or audit request (Gate 4)."""
    result = record_client_lead(
        company_or_name=payload.company_or_name,
        email=payload.email,
        division=payload.division or "General Inquiry",
        message=payload.message or "",
        domain=payload.domain or "",
    )
    if not result["gate_4_passed"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return JSONResponse(content={"ok": True, "data": result})


# Expose WSGI-compatible `app` for Azure App Service default Gunicorn runner
app = ASGIMiddleware(asgi_app)
