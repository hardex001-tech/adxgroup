"""
ADX Group (adxgroup.tech) — Main FastAPI Application Controller.
Includes:
1. Public Enterprise Landing Page (/)
2. GitHub/Cloudflare-style Auth Gate (/login) with Google, GitHub & Email Sign-In
3. Protected Client Console (/dashboard) with Domain Monitoring & Unlocked Code Fixes
4. ADX Owner Command Center (/admin) with Full Lead & Scan Telemetry
Wraps FastAPI with a2wsgi for seamless compatibility on Azure App Service (Gunicorn WSGI).
"""

from pathlib import Path
from typing import Any, Dict, Optional

from a2wsgi import ASGIMiddleware
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from core.ai_engine import ask_adx_ai_consultant, generate_ai_executive_summary
from core.auth import (
    add_monitored_domain,
    create_or_login_oauth_user,
    delete_session,
    delete_user_account,
    get_admin_command_center_data,
    get_client_dashboard_data,
    get_user_by_token,
    init_db,
    login_email_user,
    record_scan_event,
    register_email_user,
    update_user_profile,
)
from core.notifier import get_all_leads, record_client_lead
from core.scanner import normalize_domain, run_full_diagnostic

BASE_DIR = Path(__file__).resolve().parent
init_db()

asgi_app = FastAPI(
    title="ADX Group — Enterprise AI, Cloud & Cyber Systems",
    description="Official SaaS portal, client console, and 5-vector diagnostic engine for ADX Group (adxgroup.tech)",
    version="3.0.0",
)

STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

asgi_app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@asgi_app.middleware("http")
async def add_security_and_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; "
        "img-src 'self' https: data: blob:; font-src 'self' https: data:;"
    )
    return response


SESSION_COOKIE = "adx_session"


def _current_user(request: Request) -> Optional[Dict[str, Any]]:
    token = request.cookies.get(SESSION_COOKIE)
    return get_user_by_token(token)


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


class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    company: Optional[str] = ""


class LoginRequest(BaseModel):
    email: str
    password: str


class OAuthQuickRequest(BaseModel):
    provider: str
    email: str
    name: Optional[str] = ""
    company: Optional[str] = ""


class AddDomainRequest(BaseModel):
    domain: str


class ProfileUpdateRequest(BaseModel):
    name: str
    company: Optional[str] = ""


@asgi_app.post("/api/auth/profile")
async def api_update_profile(request: Request, payload: ProfileUpdateRequest):
    user = _current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    try:
        updated = update_user_profile(user["id"], payload.name, payload.company or "")
        return {"ok": True, "user": updated}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@asgi_app.post("/api/auth/delete-account")
async def api_delete_account(request: Request):
    """Permanently delete user account and invalidate session."""
    user = _current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    delete_user_account(user["id"])
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        delete_session(token)
    resp = JSONResponse(content={"ok": True, "redirect": "/login?deleted=true"})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@asgi_app.api_route("/robots.txt", methods=["GET", "HEAD"], response_class=Response)
async def robots_txt():
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        "User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /dashboard\n\nSitemap: https://adxgroup.tech/sitemap.xml\n"
    )


@asgi_app.api_route("/sitemap.xml", methods=["GET", "HEAD"], response_class=Response)
async def sitemap_xml():
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://adxgroup.tech/</loc>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://adxgroup.tech/login</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>"""
    return Response(content=xml_content, media_type="application/xml")


@asgi_app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the Public ADX Group Landing Page."""
    user = _current_user(request)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"user": user},
    )


@asgi_app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render the GitHub/Cloudflare-style Sign In / Sign Up Gate."""
    user = _current_user(request)
    if user:
        target = "/admin" if user.get("role") == "admin" else "/dashboard"
        return RedirectResponse(url=target, status_code=302)
    return templates.TemplateResponse(request=request, name="login.html")


@asgi_app.get("/logout")
async def logout(request: Request):
    """Clear session cookie and return to landing page."""
    token = request.cookies.get(SESSION_COOKIE)
    delete_session(token)
    resp = RedirectResponse(url="/login?logout=true", status_code=302)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@asgi_app.get("/dashboard", response_class=HTMLResponse)
async def client_dashboard(request: Request):
    """Render the authenticated Client Console."""
    user = _current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    dash_data = get_client_dashboard_data(user["id"])
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": user,
            "monitored_domains": dash_data["monitored_domains"],
            "recent_scans": dash_data["recent_scans"],
        },
    )


@asgi_app.get("/admin", response_class=HTMLResponse)
async def owner_admin_console(request: Request):
    """Render the ADX Group Owner Command Center (Strictly Admin Only)."""
    user = _current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    if user.get("role") != "admin":
        return RedirectResponse(url="/dashboard", status_code=302)
    admin_data = get_admin_command_center_data()
    leads = get_all_leads()
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "user": user,
            "admin_data": admin_data,
            "leads": leads,
        },
    )


def _set_auth_cookie(response: Response, token: str) -> None:
    import os
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        max_age=30 * 86400,  # 30 full days persistent cookie
        samesite="lax",
        path="/",
        secure=True if (os.getenv("VERCEL") or os.getenv("PORT") is None) else False,
    )


class AuthSyncRequest(BaseModel):
    token: Optional[str] = ""


@asgi_app.post("/api/auth/sync")
async def api_auth_sync(request: Request, payload: AuthSyncRequest):
    """Restore or refresh session cookie using localStorage token across browser restarts."""
    token = payload.token or request.cookies.get(SESSION_COOKIE)
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid.")
    redirect_to = "/admin" if user.get("role") == "admin" else "/dashboard"
    resp = JSONResponse(content={"ok": True, "user": user, "token": token, "redirect": redirect_to})
    _set_auth_cookie(resp, token)
    return resp


@asgi_app.post("/api/auth/register")
async def api_register(payload: RegisterRequest):
    try:
        sess = register_email_user(
            name=payload.name,
            email=payload.email,
            password=payload.password,
            company=payload.company or "",
        )
        redirect_to = "/admin" if sess["user"]["role"] == "admin" else "/dashboard"
        resp = JSONResponse(
            content={"ok": True, "user": sess["user"], "token": sess["token"], "redirect": redirect_to}
        )
        _set_auth_cookie(resp, sess["token"])
        return resp
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@asgi_app.post("/api/auth/login")
async def api_login(payload: LoginRequest):
    try:
        sess = login_email_user(email=payload.email, password=payload.password)
        redirect_to = "/admin" if sess["user"]["role"] == "admin" else "/dashboard"
        resp = JSONResponse(
            content={"ok": True, "user": sess["user"], "token": sess["token"], "redirect": redirect_to}
        )
        _set_auth_cookie(resp, sess["token"])
        return resp
    except ValueError as ve:
        raise HTTPException(status_code=401, detail=str(ve))


@asgi_app.post("/api/auth/oauth")
async def api_oauth_signin(payload: OAuthQuickRequest):
    if not payload.email or "@" not in payload.email:
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")
    sess = create_or_login_oauth_user(
        email=payload.email,
        name=payload.name or "",
        provider=payload.provider,
        company=payload.company or "",
    )
    redirect_to = "/admin" if sess["user"]["role"] == "admin" else "/dashboard"
    resp = JSONResponse(
        content={"ok": True, "user": sess["user"], "token": sess["token"], "redirect": redirect_to}
    )
    _set_auth_cookie(resp, sess["token"])
    return resp


@asgi_app.post("/api/domains/add")
async def api_add_monitored_domain(request: Request, payload: AddDomainRequest):
    user = _current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    clean = normalize_domain(payload.domain)
    if not clean or "." not in clean:
        raise HTTPException(status_code=400, detail="Invalid domain name.")
    add_monitored_domain(user["id"], clean)
    return {"ok": True, "domain": clean}


@asgi_app.get("/api/health")
async def health_check():
    return {
        "status": "ONLINE",
        "entity": "ADX Group (adxgroup.tech)",
        "divisions": ["ADX Cyber", "ADX Cloud & Systems", "ADX Intelligence"],
        "contact": "contact@adxgroup.tech",
    }


@asgi_app.post("/api/scan")
async def api_scan_domain(request: Request, payload: ScanRequest):
    """Run the 5-vector security diagnostic inside the authenticated Console."""
    user = _current_user(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Please sign in with Google, GitHub, or Work Email to run the 5-Vector Security Diagnostic.",
        )
    try:
        scan_data = await run_full_diagnostic(payload.domain)
        scan_data["ai_executive_summary"] = generate_ai_executive_summary(scan_data)
        record_scan_event(scan_data, user=user)
        scan_data["is_authenticated"] = True
        return JSONResponse(content={"ok": True, "data": scan_data})
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Diagnostic engine encountered an error: {str(exc)[:120]}",
        )


@asgi_app.post("/api/chat")
async def api_ai_consultant(request: Request, payload: ChatRequest):
    user = _current_user(request)
    recent_scans = []
    if user:
        dash_data = get_client_dashboard_data(user["id"])
        recent_scans = dash_data.get("recent_scans", [])
    else:
        user = {"name": "Guest", "company": "ADX Visitor"}
    result = await ask_adx_ai_consultant(
        payload.message,
        user=user,
        recent_scans=recent_scans,
    )
    return JSONResponse(content={"ok": True, "data": result})


class TtsRequest(BaseModel):
    text: str


@asgi_app.post("/api/tts")
async def api_neural_tts(payload: TtsRequest):
    """Generate studio-grade human Neural AI MP3 audio via Microsoft Edge Neural TTS."""
    import re
    import edge_tts
    from fastapi.responses import Response

    raw_text = (payload.text or "").strip()[:500]
    if not raw_text:
        raise HTTPException(status_code=400, detail="Empty text")

    # Ensure ADX is spoken strictly as the letters A. D. X. (never 'Adex' or 'ADX Group')
    clean_text = re.sub(r"\b(A\s*D\s*X|ADX|Adex)\s+Group\b", "A. D. X.", raw_text, flags=re.IGNORECASE)
    clean_text = re.sub(r"\b(A\s*D\s*X|ADX|Adex)\b", "A. D. X.", clean_text, flags=re.IGNORECASE)
    clean_text = re.sub(r"\bC\s*V\s*E\b", "C. V. E.", clean_text, flags=re.IGNORECASE)

    communicate = edge_tts.Communicate(clean_text, "en-US-AvaMultilingualNeural", rate="+0%")
    audio_bytes = bytearray()
    async for chunk in communicate.stream():
        if chunk["type"] == "audio":
            audio_bytes.extend(chunk["data"])

    return Response(content=bytes(audio_bytes), media_type="audio/mpeg")


class AdminAiTokenRequest(BaseModel):
    github_token: str


@asgi_app.post("/api/admin/ai-token")
async def api_save_ai_token(request: Request, payload: AdminAiTokenRequest):
    user = _current_user(request)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Owner access required.")
    token = (payload.github_token or "").strip()
    if len(token) < 20:
        raise HTTPException(status_code=400, detail="Please enter a valid GitHub Personal Access Token.")

    import os
    env_file = BASE_DIR / ".env"
    os.environ["GITHUB_TOKEN"] = token
    with open(env_file, "w", encoding="utf-8") as f:
        f.write(f"GITHUB_TOKEN={token}\n")

    test_res = await ask_adx_ai_consultant("Confirm ADX Neural Core is online in one sentence.", user=user)
    return JSONResponse(
        content={
            "ok": True,
            "engine": test_res.get("engine"),
            "sample_reply": test_res.get("reply"),
        }
    )


@asgi_app.post("/api/lead")
async def api_submit_lead(payload: LeadRequest):
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


# Expose native ASGI app on Vercel, or WSGI-compatible `app` for Azure Gunicorn runner
import os as _os
app = asgi_app if _os.getenv("VERCEL") else ASGIMiddleware(asgi_app)
