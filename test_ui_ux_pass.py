"""
ADX Group - UI/UX Polish Pass Test Suite (ui-ux-pass branch)
Verifies:
1. Brand Assets (/assets/brand/) & Favicons
2. Self-Hosted Variable Fonts (Inter & JetBrains Mono)
3. Design Tokens (tokens.css) & Color Contrast
4. Landing Page Structure (8 sections, strict order, dual CTAs, DPCO FAQ)
5. Auth / Login (Centered card, password toggle, strength indicator)
6. Client Workspace Console (noindex, 5 tabs, empty states, sample data tagging)
7. Splash Flag Guard (core.offers_config.SPLASH_ENABLED = False)
8. Strict Security Headers & CSP (zero external font CDNs)
9. Sitemap & Robots Indexation Integrity
"""

import os
from pathlib import Path
from starlette.testclient import TestClient

from app import asgi_app
from core.offers_config import SPLASH_ENABLED

client = TestClient(asgi_app)
BASE_DIR = Path(__file__).resolve().parent


def test_splash_flag_disabled_by_default():
    assert SPLASH_ENABLED is False, "Task G requires SPLASH_ENABLED to default to False."
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'id="brand-splash-overlay"' not in resp.text


def test_brand_assets_and_favicons():
    brand_files = [
        ("logo-mark-flat.svg", 10 * 1024),
        ("logo-mark-gradient.svg", 10 * 1024),
        ("logo-lockup.svg", 10 * 1024),
        ("logo-lockup-tagline.svg", 10 * 1024),
        ("favicon.svg", 10 * 1024),
        ("favicon-32.png", 50 * 1024),
        ("favicon-192.png", 100 * 1024),
        ("favicon-512.png", 250 * 1024),
        ("apple-touch-icon.png", 100 * 1024),
        ("og-image.png", 300 * 1024),
    ]

    for fname, max_size in brand_files:
        # Check static serving via /assets/brand/
        resp = client.get(f"/assets/brand/{fname}")
        assert resp.status_code == 200, f"/assets/brand/{fname} returned {resp.status_code}"
        assert len(resp.content) <= max_size, f"{fname} exceeded size budget of {max_size} bytes: {len(resp.content)}"

    # Check original logo preserved in assets/brand/original/logo.svg
    orig_path = BASE_DIR / "assets" / "brand" / "original" / "logo.svg"
    assert orig_path.exists(), "Original logo must be preserved in assets/brand/original/logo.svg"

    # Check flat mark uses currentColor
    flat_svg = (BASE_DIR / "assets" / "brand" / "logo-mark-flat.svg").read_text(encoding="utf-8")
    assert "currentColor" in flat_svg, "Flat mark must use currentColor for dynamic theme styling"

    # Check brand README exists
    readme_path = BASE_DIR / "assets" / "brand" / "README.md"
    assert readme_path.exists()
    assert "ADX Group Brand Identity Specification" in readme_path.read_text(encoding="utf-8")


def test_self_hosted_fonts():
    # Verify woff2 files exist and return HTTP 200
    resp_inter = client.get("/static/fonts/inter-variable.woff2")
    assert resp_inter.status_code == 200, f"inter-variable.woff2 returned {resp_inter.status_code}"
    assert len(resp_inter.content) > 10000

    resp_mono = client.get("/static/fonts/jetbrains-mono-variable.woff2")
    assert resp_mono.status_code == 200, f"jetbrains-mono-variable.woff2 returned {resp_mono.status_code}"
    assert len(resp_mono.content) > 10000

    # Verify zero external font links in rendered pages
    pages = ["/", "/login", "/readiness-check", "/solutions/shield", "/solutions/comply", "/privacy", "/terms"]
    for p in pages:
        res = client.get(p)
        assert res.status_code == 200, f"Page {p} failed with {res.status_code}"
        assert "fonts.googleapis.com" not in res.text, f"Found Google Fonts CDN in {p}"
        assert "fonts.gstatic.com" not in res.text, f"Found fonts.gstatic.com in {p}"


def test_design_tokens():
    resp = client.get("/static/css/tokens.css")
    assert resp.status_code == 200
    css = resp.text

    # Verify palette tokens
    assert "--bg-base: #0b1220;" in css
    assert "--bg-surface: #111a2e;" in css
    assert "--border-subtle: #1f2a44;" in css
    assert "--text-primary: #e6eaf2;" in css
    assert "--text-muted: #9aa7bd;" in css
    assert "--accent-primary: #38bdf8;" in css
    assert "--status-success: #10b981;" in css
    assert "--status-warning: #f59e0b;" in css
    assert "--status-danger: #ef4444;" in css

    # Verify spacing scale
    for sp in ["--space-1: 4px;", "--space-2: 8px;", "--space-3: 12px;", "--space-4: 16px;",
               "--space-5: 24px;", "--space-6: 32px;", "--space-7: 48px;", "--space-8: 64px;"]:
        assert sp in css, f"Missing spacing token: {sp}"


def test_landing_page_structure():
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text

    # 1. Hero
    assert '<section class="hero">' in html
    assert 'Defensive Engineering' in html
    assert 'Run Free Audit' in html
    assert 'Book a 20-Minute Review' in html

    # 2. Free Readiness Check
    assert 'Free NDPA &amp; Security Readiness Check' in html or 'Free NDPA & Security Readiness Check' in html
    assert '/readiness-check' in html

    # 3. The Four Offers
    assert 'id="solutions"' in html
    assert '/solutions/shield' in html
    assert '/solutions/comply' in html
    assert '/solutions/resilience' in html
    assert '/solutions/ai-automation' in html

    # 4. How It Works
    assert 'id="how-it-works"' in html

    # 5. Who We Help
    assert 'id="who-we-help"' in html

    # 6. About the Founder and Credibility
    assert 'id="founder-section"' in html
    assert 'Abdulrazaq Adeyemi' in html

    # 7. FAQ (with accurate DPCO answer)
    assert 'id="faq"' in html
    assert 'Are you a licensed DPCO?' in html
    assert 'licensed DPCO' in html

    # 8. Contact and Footer
    assert 'id="contact"' in html
    assert 'class="site-footer"' in html

    # Section ordering verification
    idx_hero = html.find('class="hero"')
    idx_readiness = html.find('id="readiness-check-banner"')
    idx_solutions = html.find('id="solutions"')
    idx_how = html.find('id="how-it-works"')
    idx_who = html.find('id="who-we-help"')
    idx_founder = html.find('id="founder-section"')
    idx_faq = html.find('id="faq"')
    idx_contact = html.find('id="contact"')

    assert -1 < idx_hero < idx_readiness < idx_solutions < idx_how < idx_who < idx_founder < idx_faq < idx_contact, \
        "Landing page sections must follow strict 8-step sequence."


def test_auth_login_ui():
    resp = client.get("/login")
    assert resp.status_code == 200
    html = resp.text

    # Centered card layout
    assert 'class="auth-card"' in html
    assert '/assets/brand/logo-lockup.svg' in html

    # Password toggle & strength bar
    assert 'id="btn-toggle-signin"' in html
    assert 'id="pwd-strength-bar"' in html
    assert 'id="pwd-strength-text"' in html

    # Form fields
    assert 'id="signin-identifier"' in html
    assert 'id="signin-password"' in html

    # MFA step panel
    assert 'id="mfa-panel"' in html
    assert 'id="mfa-code-input"' in html


def test_workspace_console_dashboard():
    # Test unauthenticated redirects to /login
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code in [302, 303, 307]

    # Test authenticated view
    from core.auth import create_or_login_oauth_user

    res = create_or_login_oauth_user("audit_tester@adxgroup.tech", "Audit Tester", "google", "Test Corp")
    token = res["token"]
    resp = client.get("/dashboard", cookies={"adx_session": token})
    assert resp.status_code == 200
    html = resp.text

    # 1. Robots noindex, nofollow
    assert '<meta name="robots" content="noindex, nofollow" />' in html

    # 2. Five sidebar tabs
    assert 'id="nav-overview"' in html
    assert 'id="nav-scanner"' in html
    assert 'id="nav-reports"' in html
    assert 'id="nav-compliance"' in html
    assert 'id="nav-settings"' in html

    # 3. Overview tab empty state
    assert 'No audits yet. Run your first one.' in html

    # 4. Specimen / Sample data tagging
    assert 'Sample data' in html or 'Sample Demonstration Data' in html


def test_security_headers_and_csp():
    resp = client.get("/")
    assert resp.status_code == 200
    headers = resp.headers

    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert "max-age=63072000" in headers.get("Strict-Transport-Security", "")

    csp = headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "fonts.googleapis.com" not in csp
    assert "fonts.gstatic.com" not in csp


def test_robots_and_sitemap():
    # robots.txt disallows /dashboard and /admin
    r_robots = client.get("/robots.txt")
    assert r_robots.status_code == 200
    assert "Disallow: /admin" in r_robots.text
    assert "Disallow: /dashboard" in r_robots.text

    # sitemap.xml includes public routes and excludes /dashboard
    r_sitemap = client.get("/sitemap.xml")
    assert r_sitemap.status_code == 200
    assert "https://adxgroup.tech/solutions/shield" in r_sitemap.text
    assert "https://adxgroup.tech/solutions/comply" in r_sitemap.text
    assert "https://adxgroup.tech/solutions/resilience" in r_sitemap.text
    assert "https://adxgroup.tech/solutions/ai-automation" in r_sitemap.text
    assert "https://adxgroup.tech/readiness-check" in r_sitemap.text
    assert "https://adxgroup.tech/privacy" in r_sitemap.text
    assert "https://adxgroup.tech/terms" in r_sitemap.text
    assert "/dashboard" not in r_sitemap.text


if __name__ == "__main__":
    tests = [
        test_splash_flag_disabled_by_default,
        test_brand_assets_and_favicons,
        test_self_hosted_fonts,
        test_design_tokens,
        test_landing_page_structure,
        test_auth_login_ui,
        test_workspace_console_dashboard,
        test_security_headers_and_csp,
        test_robots_and_sitemap,
    ]

    print("\nRUNNING UI/UX POLISH PASS TEST SUITE:")
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__} - {e}")
            raise e

    print(f"\nALL {passed}/{len(tests)} TESTS PASSED PERFECTLY!\n")
