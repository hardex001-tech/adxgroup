"""
ADX Group — Automated Placeholder Guard & Verification Test Suite.
Verifies that no '[PLACEHOLDER' or 'PLACEHOLDER:' string ever leaks into
rendered public HTML, meta tags, attributes, JSON-LD, XML, or robots.txt.
"""

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


def test_confirmed_founder_values():
    """Verify that confirmed founder values render correctly."""
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text

    # Confirmed WhatsApp number is active and links properly
    assert "whatsapp-float-btn" in html
    assert "https://wa.me/2349136168678" in html

    # Mandated DPCO notice is exact
    assert "Under the NDPA, annual Compliance Audit Returns must be filed through a licensed DPCO. ADX Group is not a DPCO and does not file them." in html

    # Booking CTA falls back to #contact when BOOKING_URL is empty
    assert 'href="#contact"' in html

    # CAC line is omitted when empty
    assert "(RC " not in html
    assert "CAC" not in html

    # Sample audit report PDF link is valid
    assert "/static/reports/sample-audit-report.pdf" in html

    print("  PASS: test_confirmed_founder_values")


def test_solution_pages_pricing_and_dpco_wording():
    """Verify ADX Shield price and fallback pricing across remaining solution offers."""
    # 1. ADX Shield has confirmed starting price
    resp_shield = client.get("/solutions/shield")
    assert resp_shield.status_code == 200
    html_shield = resp_shield.text
    assert "From ₦150,000" in html_shield
    assert "per domain, scope confirmed in a written quote" in html_shield
    assert "Pilot Offering" in html_shield

    # 2. Other offers show "Contact us for pricing"
    for slug in ["comply", "resilience", "ai-automation"]:
        resp = client.get(f"/solutions/{slug}")
        assert resp.status_code == 200
        html = resp.text
        assert "PLACEHOLDER" not in html
        assert "Contact us for pricing" in html
        assert "Engagement Timeline" not in html
        assert 'href="/#contact"' in html

    # 3. Comply page has exact mandated DPCO wording
    resp_comply = client.get("/solutions/comply")
    assert "Under the NDPA, annual Compliance Audit Returns must be filed through a licensed DPCO. ADX Group is not a DPCO and does not file them." in resp_comply.text

    print("  PASS: test_solution_pages_pricing_and_dpco_wording")


def test_empty_config_guards():
    """Verify that if WHATSAPP_NUMBER is cleared, the buttons disappear completely."""
    original_wa = pcfg.WHATSAPP_NUMBER

    try:
        pcfg.WHATSAPP_NUMBER = ""
        assert pcfg.get_whatsapp_url() == ""

        resp = client.get("/")
        assert resp.status_code == 200
        assert "whatsapp-float-btn" not in resp.text
        assert "wa.me" not in resp.text
    finally:
        pcfg.WHATSAPP_NUMBER = original_wa

    print("  PASS: test_empty_config_guards")


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
    test_confirmed_founder_values()
    test_solution_pages_pricing_and_dpco_wording()
    test_empty_config_guards()
    test_malformed_or_placeholder_injection_safety()
    print("\nALL PLACEHOLDER GUARD TESTS PASSED PERFECTLY!\n")
