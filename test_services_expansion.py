from starlette.testclient import TestClient
import app
from app import asgi_app
from core.offers_data import OFFERS_DICT, READINESS_QUESTIONS, SECTORS_LIST

client = TestClient(asgi_app)

def test_home_page():
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text
    # Solutions section & cards
    assert 'id="solutions"' in html
    assert "ADX Shield" in html
    assert "ADX Comply" in html
    assert "ADX Resilience" in html
    assert "ADX AI and Automation" in html
    # Task B: Sectors ("Who we help")
    assert 'id="who-we-help"' in html
    assert "Fintech" in html
    assert "Insurance" in html
    assert "Healthcare" in html
    assert "EdTech" in html
    assert "Logistics" in html
    # NDPA Urgency Notice
    assert "Nigeria Data Protection Act (NDPA) 2023 Compliance Mandate" in html
    assert "licensed DPCO" in html
    # Task E: How we work & Partners
    assert "Scoped &amp; Authorized (NDA First)" in html or "Scoped & Authorized (NDA First)" in html
    assert "Prioritized Remediation Roadmap" in html
    assert "Post-Fix Re-Testing" in html
    assert "Cloudflare" in html
    assert "Vercel" in html
    assert "Zoho Mail" in html
    # WhatsApp Float button appears when WHATSAPP_NUMBER is confirmed
    assert "whatsapp-float-btn" in html
    # Currency toggle
    assert "currency-btn" in html
    assert "setOfferCurrency('NGN')" in html
    print("  PASS: test_home_page")

def test_solution_pages():
    for slug, offer in OFFERS_DICT.items():
        resp = client.get(f"/solutions/{slug}")
        assert resp.status_code == 200, f"Failed for /solutions/{slug}"
        html = resp.text
        assert offer["name"] in html
        assert "Service" in html  # JSON-LD Schema
        assert "BreadcrumbList" in html
        assert "What We Deliver" in html
        assert "How an Engagement Works" in html
        assert "What Is NOT Included" in html
        assert "price-val" in html
        # WhatsApp button renders
        assert "whatsapp-float-btn" in html
        print(f"  PASS: /solutions/{slug}")

def test_comply_page_dpco_notice():
    resp = client.get("/solutions/comply")
    assert resp.status_code == 200
    html = resp.text
    assert "Statutory Transparency Notice" in html
    assert "licensed DPCO" in html
    print("  PASS: test_comply_page_dpco_notice")

def test_invalid_solution_404():
    resp = client.get("/solutions/non-existent-solution")
    assert resp.status_code == 404
    print("  PASS: test_invalid_solution_404")

def test_readiness_check_page():
    resp = client.get("/readiness-check")
    assert resp.status_code == 200
    html = resp.text
    assert "Readiness Check" in html
    assert "Important Regulatory Notice" in html
    assert "readiness-quiz-form" in html
    for q in READINESS_QUESTIONS:
        assert q["id"] in html
    assert "quiz-result-box" in html
    assert "lead-consent" in html
    assert "whatsapp-float-btn" in html
    print("  PASS: test_readiness_check_page")

def test_readiness_api_consent_required():
    payload = {
        "name": "Test User",
        "email": "test@company.com",
        "company": "Test Co",
        "sector": "Fintech & Payments",
        "score": 6,
        "risk_band": "Medium",
        "consent": False
    }
    resp = client.post("/api/readiness-check", json=payload)
    assert resp.status_code == 400
    assert "Consent is required" in resp.json()["detail"]
    print("  PASS: test_readiness_api_consent_required")

def test_readiness_api_honeypot_silently_discards():
    payload = {
        "name": "Bot Spammer",
        "email": "bot@spam.com",
        "company": "Spam Corp",
        "sector": "Other",
        "score": 0,
        "risk_band": "High",
        "consent": True,
        "hp_token": "spam_bot_data"
    }
    resp = client.post("/api/readiness-check", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "Readiness assessment received" in data["message"]
    print("  PASS: test_readiness_api_honeypot_silently_discards")

def test_readiness_api_valid_submission_and_rate_limit():
    app._SCAN_RATE_LIMITS.clear()
    for i in range(5):
        payload = {
            "name": f"Client {i}",
            "email": f"client{i}@zenithmicro.ng",
            "company": "Zenith Microfinance Bank",
            "sector": "Fintech & Payments",
            "score": 7,
            "risk_band": "Medium",
            "consent": True
        }
        resp = client.post("/api/readiness-check", json=payload)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    # 6th request triggers rate limit
    payload_6th = {
        "name": "Client 6",
        "email": "client6@zenithmicro.ng",
        "company": "Zenith Microfinance Bank",
        "sector": "Fintech & Payments",
        "score": 7,
        "risk_band": "Medium",
        "consent": True
    }
    resp_6th = client.post("/api/readiness-check", json=payload_6th)
    assert resp_6th.status_code == 429
    assert "rate limit exceeded" in resp_6th.json()["detail"]
    print("  PASS: test_readiness_api_valid_submission_and_rate_limit")

def test_privacy_policy_documents_readiness():
    resp = client.get("/privacy")
    assert resp.status_code == 200
    html = resp.text
    assert "Readiness Check" in html
    print("  PASS: test_privacy_policy_documents_readiness")

def test_sitemap_contains_new_urls():
    resp = client.get("/sitemap.xml")
    assert resp.status_code == 200
    xml = resp.text
    assert "https://adxgroup.tech/solutions/shield" in xml
    assert "https://adxgroup.tech/solutions/comply" in xml
    assert "https://adxgroup.tech/solutions/resilience" in xml
    assert "https://adxgroup.tech/solutions/ai-automation" in xml
    assert "https://adxgroup.tech/readiness-check" in xml
    print("  PASS: test_sitemap_contains_new_urls")

def test_security_headers():
    resp = client.get("/")
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Strict-Transport-Security" in resp.headers
    assert "Content-Security-Policy" in resp.headers
    print("  PASS: test_security_headers")

if __name__ == "__main__":
    print("RUNNING SERVICES EXPANSION TEST SUITE:")
    test_home_page()
    test_solution_pages()
    test_comply_page_dpco_notice()
    test_invalid_solution_404()
    test_readiness_check_page()
    test_readiness_api_consent_required()
    test_readiness_api_honeypot_silently_discards()
    test_readiness_api_valid_submission_and_rate_limit()
    test_privacy_policy_documents_readiness()
    test_sitemap_contains_new_urls()
    test_security_headers()
    print("\nALL TEST SUITES PASSED PERFECTLY!")
