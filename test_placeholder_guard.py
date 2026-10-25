"""
ADX Group — Automated Placeholder Guard & Verification Test Suite.
Verifies that no '[PLACEHOLDER' or 'PLACEHOLDER:' string ever leaks into
rendered public HTML, meta tags, attributes, JSON-LD, XML, or robots.txt.
"""

import re
from starlette.testclient import TestClient
from app import asgi_app
import core.public_config as pcfg
from core.offers_data import OFFERS_DICT

client = TestClient(asgi_app)

PUBLIC_ROUTES = [
    "/",
    "/solutions/shield",
    "/solutions/comply",
    "/solutions/resilience",
    "/solutions/ai-automation",
    "/readiness-check",
    "/security",
    "/login",
    "/privacy",
    "/terms",
    "/cookies",
    "/do-not-sell",
    "/sitemap.xml",
    "/robots.txt",
]


def test_zero_placeholders_rendered():
    """Verify that no route ever contains 'PLACEHOLDER' in rendered output."""
    for route in PUBLIC_ROUTES:
        resp = client.get(route)
        assert resp.status_code == 200, f"Route {route} returned status {resp.status_code}"
        text = resp.text
        assert "PLACEHOLDER" not in text, (
            f"VIOLATION: 'PLACEHOLDER' string found in rendered output of {route}!"
        )
        assert "[PLACEHOLDER" not in text, f"Found [PLACEHOLDER in {route}"
        assert "PLACEHOLDER:" not in text, f"Found PLACEHOLDER: in {route}"
    print("  PASS: test_zero_placeholders_rendered across all public routes")


def test_default_empty_guards():
    """Verify that when config values are empty, UI elements are safely omitted."""
    # 1. Homepage with empty defaults
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text

    # WhatsApp buttons must not render when WHATSAPP_NUMBER is empty
    assert "whatsapp-float-btn" not in html
    assert "Chat on WhatsApp" not in html
    assert "wa.me" not in html

    # Booking CTA must fallback to #contact
    assert 'href="#contact"' in html

    # CAC line must be omitted
    assert "(RC " not in html
    assert "CAC" not in html

    # Social icons omitted when URLs empty
    assert 'title="ADX LinkedIn"' not in html
    assert 'title="ADX on X"' not in html

    # DPCO partner block omitted when DPCO_PARTNER_NAME empty
    assert "Licensed DPCO Partner" not in html
    assert "Annual NDPC filings are made through a licensed DPCO." in html

    # FAQ honest answer
    assert "Are you a licensed DPCO?" in html
    assert "<strong>No.</strong> ADX Group is an engineering consultancy" in html

    # Sample audit report PDF link is valid
    assert "/static/reports/sample-audit-report.pdf" in html

    print("  PASS: test_default_empty_guards")


def test_solution_pages_empty_pricing_and_timeline():
    """Verify solutions pages hide empty timelines and display 'Contact us for pricing'."""
    for slug in OFFERS_DICT.keys():
        resp = client.get(f"/solutions/{slug}")
        assert resp.status_code == 200
        html = resp.text

        # No placeholders
        assert "PLACEHOLDER" not in html
        assert "[PLACEHOLDER" not in html

        # Pricing fallback
        assert "Contact us for pricing" in html

        # Timeline block omitted when empty
        assert "Engagement Timeline" not in html

        # Booking falls back to /#contact
        assert 'href="/#contact"' in html

        # WhatsApp button omitted
        assert "whatsapp-float-btn" not in html
    print("  PASS: test_solution_pages_empty_pricing_and_timeline")


def test_populated_config_behavior(monkeypatch=None):
    """Verify formatting when real configuration values are supplied."""
    original_wa = pcfg.WHATSAPP_NUMBER
    original_booking = pcfg.BOOKING_URL
    original_linkedin = pcfg.LINKEDIN_URL
    original_dpco = pcfg.DPCO_PARTNER_NAME
    original_cac = pcfg.CAC_NAME_AND_RC

    try:
        pcfg.WHATSAPP_NUMBER = "+234 801 234 5678"
        pcfg.BOOKING_URL = "https://cal.com/adxgroup/review"
        pcfg.LINKEDIN_URL = "https://www.linkedin.com/company/adxgroup"
        pcfg.DPCO_PARTNER_NAME = "Verified DPCO Partners Ltd"
        pcfg.CAC_NAME_AND_RC = "ADX GROUP TECHNOLOGIES LTD (RC 1928374)"

        # Check WhatsApp link builder
        wa_url = pcfg.get_whatsapp_url()
        assert wa_url.startswith("https://wa.me/2348012345678?text=")

        # Check Booking URL getter
        assert pcfg.get_booking_url() == "https://cal.com/adxgroup/review"

        # Check DPCO name getter
        assert pcfg.get_dpco_partner_name() == "Verified DPCO Partners Ltd"

        # Render homepage with populated values
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert "whatsapp-float-btn" in html
        assert "https://wa.me/2348012345678" in html
        assert "https://cal.com/adxgroup/review" in html
        assert "Verified DPCO Partners Ltd" in html
        assert "RC 1928374" in html
        assert 'title="ADX LinkedIn"' in html

        # Still strictly zero PLACEHOLDER strings
        assert "PLACEHOLDER" not in html
        assert "[PLACEHOLDER" not in html

    finally:
        pcfg.WHATSAPP_NUMBER = original_wa
        pcfg.BOOKING_URL = original_booking
        pcfg.LINKEDIN_URL = original_linkedin
        pcfg.DPCO_PARTNER_NAME = original_dpco
        pcfg.CAC_NAME_AND_RC = original_cac

    print("  PASS: test_populated_config_behavior")


def test_malformed_or_placeholder_injection_safety():
    """Verify that if an env var contains 'PLACEHOLDER', getters sanitize it to empty string."""
    original_wa = pcfg.WHATSAPP_NUMBER
    original_dpco = pcfg.DPCO_PARTNER_NAME

    try:
        pcfg.WHATSAPP_NUMBER = "[PLACEHOLDER: WhatsApp number]"
        pcfg.DPCO_PARTNER_NAME = "[PLACEHOLDER: partner DPCO name]"

        assert pcfg.get_whatsapp_url() == ""
        assert pcfg.get_dpco_partner_name() == ""

        resp = client.get("/")
        assert resp.status_code == 200
        assert "PLACEHOLDER" not in resp.text
        assert "[PLACEHOLDER" not in resp.text
    finally:
        pcfg.WHATSAPP_NUMBER = original_wa
        pcfg.DPCO_PARTNER_NAME = original_dpco

    print("  PASS: test_malformed_or_placeholder_injection_safety")


if __name__ == "__main__":
    print("\nRUNNING PLACEHOLDER GUARD TEST SUITE:")
    test_zero_placeholders_rendered()
    test_default_empty_guards()
    test_solution_pages_empty_pricing_and_timeline()
    test_populated_config_behavior()
    test_malformed_or_placeholder_injection_safety()
    print("\nALL PLACEHOLDER GUARD TESTS PASSED PERFECTLY!\n")
