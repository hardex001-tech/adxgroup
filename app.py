"""Small FastAPI site for the ADX Group student portfolio."""

import os
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr

BASE_DIR = Path(__file__).resolve().parent

asgi_app = FastAPI(
    title="ADX Group | Student developer portfolio",
    description="A simple portfolio for Abdulrazaq Adeyemi.",
    version="1.0.0",
)
# Vercel's Python runtime looks for the conventional `app` entrypoint.
app = asgi_app

asgi_app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
asgi_app.mount("/assets", StaticFiles(directory=str(BASE_DIR / "assets")), name="assets")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asgi_app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith(("/static/", "/assets/")):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    else:
        response.headers["Cache-Control"] = "no-store"
    response.headers.update(
        {
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "font-src 'self'; img-src 'self' data:; connect-src 'self'; "
                "frame-ancestors 'none'; object-src 'none'; base-uri 'self';"
            ),
        }
    )
    return response


class ContactRequest(BaseModel):
    name: str
    email: EmailStr
    message: str
    website: str = ""


_contact_timestamps: Dict[str, List[float]] = {}


def _limited(client_key: str) -> bool:
    now = time.time()
    recent = [stamp for stamp in _contact_timestamps.get(client_key, []) if now - stamp < 600]
    if len(recent) >= 3:
        _contact_timestamps[client_key] = recent
        return False
    recent.append(now)
    _contact_timestamps[client_key] = recent
    return True


@asgi_app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request},
    )


@asgi_app.get("/api/health")
async def health():
    return {"status": "ok", "service": "adxgroup-portfolio"}


@asgi_app.post("/api/contact")
async def contact(request: Request, payload: ContactRequest):
    if payload.website:
        return {"ok": True, "message": "Thanks — I’ll get back to you soon."}
    if not _limited(request.client.host if request.client else "unknown"):
        raise HTTPException(status_code=429, detail="Too many messages. Please try again later.")
    if not payload.name.strip() or not payload.message.strip():
        raise HTTPException(status_code=400, detail="Name and message are required.")
    if len(payload.message.strip()) > 2000:
        raise HTTPException(status_code=400, detail="Message must be under 2,000 characters.")
    smtp_password = os.getenv("SMTP_PASSWORD") or os.getenv("ZOHO_PASSWORD")
    if not smtp_password:
        raise HTTPException(
            status_code=503,
            detail="Contact email is not configured. Please email contact@adxgroup.tech directly.",
        )

    email = EmailMessage()
    email["From"] = "contact@adxgroup.tech"
    email["To"] = "contact@adxgroup.tech"
    email["Reply-To"] = str(payload.email)
    email["Subject"] = f"Portfolio message from {payload.name.strip()}"
    email.set_content(
        f"Name: {payload.name.strip()}\n"
        f"Email: {payload.email}\n\n"
        f"Message:\n{payload.message.strip()}\n"
    )
    try:
        with smtplib.SMTP_SSL("smtp.zoho.com", 465, timeout=15) as smtp:
            smtp.login("contact@adxgroup.tech", smtp_password)
            smtp.send_message(email)
    except (OSError, smtplib.SMTPException) as exc:
        raise HTTPException(
            status_code=502,
            detail="The message could not be delivered. Please email contact@adxgroup.tech directly.",
        ) from exc
    return {"ok": True, "message": "Thanks — I’ll get back to you soon."}


@asgi_app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return "User-agent: *\nAllow: /\nSitemap: https://adxgroup.tech/sitemap.xml\n"


@asgi_app.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap():
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://adxgroup.tech/</loc></url></urlset>"
    )


@asgi_app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=404, content={"ok": False, "detail": "Not found."})
    return templates.TemplateResponse(
        request=request,
        name="404.html",
        context={"request": request},
        status_code=404,
    )
