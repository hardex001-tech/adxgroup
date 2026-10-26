# ADX Group (adxgroup.tech) — Pre-Launch Architecture & Security Audit Report

**Audit Date:** October 25, 2026  
**Auditor Role:** Senior Full-Stack Engineer & Application-Security Reviewer  
**Target Domain:** https://adxgroup.tech  
**Git Branch:** `final-cleanup`  

---

## 1. Architecture Summary

- **Framework & Runtime:** Python 3.13 / FastAPI (>=0.110.0), Uvicorn (>=0.29.0), A2WSGI (>=1.10.0), Starlette, Jinja2 (>=3.1.3), Pydantic (>=2.7.0), HTTPX (>=0.27.0), dnspython (>=2.6.1). Deployed as ASGI serverless runtime via `@vercel/python`.
- **Application Entry Points:**
  - `app.py`: Main FastAPI ASGI instance (`asgi_app = FastAPI(...)`), wrapped with `ASGIMiddleware(asgi_app)` for Vercel production hosting.
  - `run.py`: Local development server running Uvicorn on port 8000.
  - `vercel.json`: Directs all routes `/(.*)` to `app.py` and enforces strict HTTP response headers.
- **Routes & API Endpoints (41 total):**
  - *Public UI Pages (14):* `/`, `/login`, `/dashboard`, `/admin`, `/security`, `/privacy`, `/terms`, `/cookies`, `/do-not-sell`, `/readiness-check`, `/solutions/shield`, `/solutions/comply`, `/solutions/resilience`, `/solutions/ai-automation`.
  - *Diagnostic & Public APIs (6):* `/api/health`, `/api/scan`, `/api/lead`, `/api/readiness-check`, `/api/chat`, `/api/tts`.
  - *Auth & Session Endpoints (16):* `/api/auth/register`, `/api/auth/login`, `/api/auth/verify-2fa`, `/api/auth/resend-2fa`, `/api/auth/verify`, `/api/auth/resend-verify`, `/api/auth/forgot-password`, `/api/auth/reset-password`, `/api/auth/verify-code`, `/api/auth/oauth`, `/api/auth/google/login`, `/api/auth/google/callback`, `/api/auth/microsoft/login`, `/api/auth/github/login`, `/api/auth/apple/login`, `/api/auth/profile`, `/api/auth/delete-account`.
  - *System & Deliverables (5):* `/sitemap.xml`, `/robots.txt`, `/static/reports/sample-audit-report.pdf`, `/api/domains/add`, `/api/admin/ai-token`.
- **Database & Data Storage:**
  - SQLite database (`adxgroup.db`) accessed via Python `sqlite3` in `core/auth.py`.
  - Tables: `users`, `sessions`, `monitored_domains`, `scans`, `deleted_accounts`.
  - Storage path: Ephemeral `Path("/tmp/adxgroup_data")` on Vercel, persistent `Path("data/")` locally.
  - JSON ledgers: `data/leads.json` (inbound contact form leads) and `data/outbox.json` (email queue).
  - *Architectural Notice:* Vercel serverless containers do not persist `/tmp` across restarts/scaling events.
- **Environment Variable Names (Names only — zero secrets):**
  `APPLE_CLIENT_ID`, `APP_BASE_URL`, `BOOKING_URL`, `BREVO_API_KEY`, `CAC_NAME_AND_RC`, `DPCO_PARTNER_NAME`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_COPILOT_TOKEN`, `GITHUB_TOKEN`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `LINKEDIN_URL`, `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `PORT`, `PRICE_AI_NGN`, `PRICE_AI_USD`, `PRICE_COMPLY_NGN`, `PRICE_COMPLY_USD`, `PRICE_RESILIENCE_NGN`, `PRICE_RESILIENCE_USD`, `PRICE_SHIELD_NGN`, `PRICE_SHIELD_USD`, `RESEND_API_KEY`, `SESSION_SECRET`, `SMTP_FROM`, `SMTP_HOST`, `SMTP_PASSWORD`, `SMTP_PORT`, `SMTP_USER`, `TIMELINE_AI`, `TIMELINE_COMPLY`, `TIMELINE_RESILIENCE`, `TIMELINE_SHIELD`, `TWITTER_URL`, `VERCEL`, `WHATSAPP_NUMBER`.
- **Deployment Config:** `vercel.json` provides strict Content-Security-Policy (self-hosted fonts, zero external CDN scripts), HSTS (63,072,000s with preload), X-Content-Type-Options: nosniff, and X-Frame-Options: DENY.
- **Existing Test Coverage:**
  - `test_placeholder_guard.py`: 5 tests (zero placeholders across 14 public routes, fallback guards).
  - `test_services_expansion.py`: 14 tests (solution pages, readiness check API, honeypot, rate limits).
  - `test_ui_ux_pass.py`: 9 tests (tokens, fonts, brand vectors, 8-section layout, dashboard shell, CSP).

---

## 2. Feature-Status Table

| Feature / Component | Status | Code & Operational Findings |
| :--- | :--- | :--- |
| **Home (`/`)** | **Works** | Fully functional 8-section responsive landing page, zero placeholder strings, working links, mobile navigation, hero diagnostic input. |
| **Solution Pages (`/solutions/*`)** | **Works** | 4 complete pages (`shield`, `comply`, `resilience`, `ai-automation`) with target audience, deliverables, exclusions, and contact CTAs. |
| **Readiness Check** | **Works** | Interactive 10-question self-assessment, client-side scoring, sector risk-banding, honeypot trap, and consent-enforced API. |
| **Contact Form (`/api/lead`)** | **Simulated / Partial** | Validates input and logs to `leads.json` in `DATA_DIR`. Does **not** dispatch email to `contact@adxgroup.tech`. Leads stored in `/tmp` on Vercel are ephemeral. |
| **Login (`/login`)** | **Partial / Local Only** | Works on persistent local SQLite. On Vercel, accounts stored in `/tmp/adxgroup.db` disappear across lambda container cycles. |
| **SSO Providers** | **Unverified / Incomplete** | Google OAuth handlers exist; Client ID/Secret configured in `.env`. Microsoft, GitHub, and Apple OAuth handlers exist but lack environment credentials. |
| **MFA / 2FA** | **Simulated in Prod** | Anomalous-IP detection generates a 6-digit OTP code in `core/auth.py`. But because `SMTP_PASSWORD` is unset, the OTP is written to local `/tmp/outbox.json` rather than emailed to the user. |
| **Login Alert Emails** | **Simulated in Prod** | `send_login_alert` logic exists in `core/mailer.py`, but writes to local `outbox.json` when `SMTP_PASSWORD` is unset. |
| **Password Hashing** | **Works** | PBKDF2-HMAC-SHA256 with 120,000 iterations and a 16-byte random hex salt (`secrets.token_hex(16)`), verified via `secrets.compare_digest`. |
| **Sample Report Download** | **Works** | Valid 3,528-byte watermarked specimen PDF exists at `static/reports/sample-audit-report.pdf` and downloads cleanly. |
| **Audit Tool (`/api/scan`)** | **Simulated / Demo** | Executes real DNS and HTTP banner queries via `core/scanner.py`, but dashboard scoring is capped; hero terminal is labeled as a demonstration preview. |

---

## 3. Top 10 Security Risks, Ranked

1. **Hardcoded Fallback Secret in Auth Token Logic (High):** In `core/auth.py:19`, `AUTH_SECRET_KEY = os.getenv("SESSION_SECRET", "adx_zerotrust_session_secret_key_2026_xploit")`. If `SESSION_SECRET` is unset in Vercel, anyone can forge signed HMAC-SHA256 session tokens for arbitrary user IDs.
2. **Ephemeral Storage Data Loss on Vercel (High):** Leads (`leads.json`), user records (`adxgroup.db`), and outbox entries are stored in `/tmp/adxgroup_data`. Vercel serverless containers recycle regularly, causing permanent loss of prospective client inquiries and client accounts.
3. **Contact Inquiries Not Dispatched to Inbox (High):** `POST /api/lead` in `core/notifier.py` only writes to local disk; it does not trigger SMTP dispatch or a third-party transactional email API. Prospective client submissions never reach `contact@adxgroup.tech`.
4. **Missing Production DMARC Record on adxgroup.tech (High):** Live DNS lookup verifies `_dmarc.adxgroup.tech` is `NXDOMAIN` (no record) and SPF is `~all` (softfail). Attackers can forge unauthenticated emails claiming to originate from `@adxgroup.tech`.
5. **Lack of Account Lockout on Failed Login Attempts (Medium):** `login_email_user` in `core/auth.py` validates passwords with PBKDF2 but does not increment a failed attempt counter or lock accounts after repeated bad credentials.
6. **Passive Scanner SSRF / Metadata Exposure Risk (Medium):** `POST /api/scan` accepts arbitrary user domain input. While regex checks exist, socket-level post-resolution validation is needed to block private (RFC 1918), loopback (127.0.0.0/8), link-local, and cloud metadata (169.254.169.254) IP addresses.
7. **2FA User Lockout Trap in Production (Medium):** Anomalous-IP detection enforces a 6-digit OTP code on sign-in. Because outbound SMTP is unconfigured in production, the code cannot be emailed to the user, blocking access.
8. **Admin Console Accessible via Token Forgery (Medium):** The `/admin` console (`app.py:385`) is gated solely on `user.get("role") == "admin"`. If signed tokens are forged via the fallback secret, the administrative command center is exposed.
9. **CORS Configuration on Sensitive Endpoints (Low/Medium):** Need to ensure all sensitive API routes strictly deny wildcard `*` origins and restrict access to `https://adxgroup.tech`.
10. **Prompt Injection Boundary in Copilot API Relay (Low):** `POST /api/chat` in `core/ai_engine.py` passes user messages to the GitHub Copilot API. Strict character limits and input sanitization should be enforced.

---

## 4. Public Claims the Code Does Not Support

1. **DPCO Partner Wording:**
   - *File:* `core/offers_data.py` (L12-L24, L108) & `templates/index.html` (L940)
   - *Current Text:* *"We work in direct partnership with our licensed DPCO partner ({{ dpco_name }})..."* or *"Annual NDPC filings are made through a licensed DPCO."*
   - *Ground Truth:* Mandated exact factual wording must be applied: *"Under the NDPA, annual Compliance Audit Returns must be filed through a licensed DPCO. ADX Group is not a DPCO and does not file them."*
2. **Pricing & Offering Description on ADX Shield:**
   - *File:* `templates/solution_page.html` (L166-L174) & `templates/index.html`
   - *Current Text:* Shows *"Contact us for pricing"* with no starting benchmark.
   - *Ground Truth:* Founder has confirmed starting price: *"From ₦150,000"* with *"per domain, scope confirmed in a written quote"*. It is a pilot offering, not a fully operational product.
3. **Console Login & SSO Provider Public Description:**
   - *File:* `templates/index.html` (L995)
   - *Current Text:* *"Google OAuth 2.0 single sign-on, adaptive 6-digit anomalous IP 2FA challenges, and automated login security alert emails. Enterprise SSO integration (Microsoft Azure AD / Entra ID, GitHub, Apple) is supported..."*
   - *Ground Truth:* In production on Vercel, SQLite is ephemeral, SMTP is disabled, and Microsoft/GitHub/Apple SSO credentials are not active. Login should be marked as "Coming soon" with waitlist capture, or truthfully described.
4. **Zero-Downtime Guarantee:**
   - *File:* `templates/index.html` (L536)
   - *Current Text:* *"architected for zero-downtime reliability and low cloud burn."*
   - *Ground Truth:* Code and single-serverless deployment cannot guarantee zero downtime. Must say: *"designed for high availability and reliability"*.
5. **AI Consultation Fixed Pricing References in Engine Prompt:**
   - *File:* `core/ai_engine.py` (L184, L187)
   - *Current Text:* Mentions *"ADX Authenticated Deep Penetration Audit ($350 fixed scope)"* and *"Deploy Fix with ADX ($350)"*.
   - *Ground Truth:* Violates single pricing structure and invents an unverified $350 tier.

---

## 5. Email Provider Evidence from MX / Config

- **Live DNS MX Query for `adxgroup.tech`:**
  - `mx.zoho.com` (Priority 10)
  - `mx2.zoho.com` (Priority 20)
  - `mx3.zoho.com` (Priority 50)
- **Domain Verification TXT:** `zoho-verification=zb80833543.zmverify.zoho.com`
- **SPF TXT Record:** `v=spf1 include:_spf.mx.cloudflare.net include:zohomail.com ~all`
- **DKIM DNS Record:** Found active at selector `zmail._domainkey.adxgroup.tech` (`v=DKIM1; k=rsa; p=MIGfMA0GCS...`).
- **DMARC Record:** `_dmarc.adxgroup.tech` returned `NXDOMAIN` (No DMARC record exists).
- **Codebase SMTP Config:** `core/mailer.py` specifies `SMTP_HOST = "smtp.zoho.com"`, `SMTP_PORT = 465`, `SMTP_USER = "contact@adxgroup.tech"`. In production, `SMTP_PASSWORD` is currently unset.
- **Verdict:** Zoho Mail is the authentic, verified corporate mail host for `adxgroup.tech`. However, outbound sending via application SMTP is inactive until `SMTP_PASSWORD` is supplied, and DMARC enforcement is missing from the public DNS zone.
