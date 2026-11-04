from starlette.testclient import TestClient

from app import asgi_app


client = TestClient(asgi_app)


def test_portfolio_home_is_simple_and_complete():
    response = client.get("/")
    assert response.status_code == 200
    assert "Understand systems.<br><em>Defend them better.</em>" in response.text
    assert "Abdulrazaq Adeyemi" in response.text
    assert "Founder, ADX Group" in response.text
    assert "Electrical Maintenance Technician" in response.text
    assert "B.Sc. Cybersecurity" in response.text
    assert "CV coming soon" in response.text
    assert "Student Community Leader" in response.text
    assert 'id="projects"' in response.text
    assert 'id="community"' in response.text
    assert 'id="contact"' in response.text
    assert "S3 Shield Defense" in response.text
    assert "NetGuard Scanner" in response.text
    assert "Canary Deception Trap" in response.text
    assert "SQL Injection Exploitation Lab" in response.text
    assert "Professional development" in response.text
    assert "Hands-on Security Practice" in response.text
    assert "View repository" in response.text
    assert "Send a message" in response.text
    assert "🛡️" not in response.text
    assert "⚡" not in response.text
    assert "🎯" not in response.text
    assert "🔐" not in response.text
    assert "https://github.com/hardex001-tech/S3-Shield-Protocol-Defense-Lab" in response.text
    assert "https://github.com/hardex001-tech/netguard-scanner" in response.text
    assert "https://github.com/hardex001-tech/Canary-Poison-Deception-Trap" in response.text
    assert "https://github.com/hardex001-tech/sql-injection-payroll-lab" in response.text
    assert 'name="scope"' in response.text
    assert "Lead Defensive Engineer" not in response.text
    assert "SC-900" in response.text
    assert "Cybersecurity Professional Certificate" in response.text
    assert "In Progress" in response.text
    assert "https://profile.hackthebox.com/profile/019d17d7-f0a3-73d1-a277-93c2bc8890ce" in response.text
    assert "Sentinel-X — Academic Capstone Architecture" in response.text
    assert "https://github.com/hardex001-tech/Sentinel-X" not in response.text
    assert "AWS Student Cloud Community" in response.text
    assert "Builder of ADX" not in response.text
    assert "SURFACE SCAN" not in response.text
    assert "Security operations" not in response.text
    assert "The security arsenal" in response.text
    assert "Direct dispatch" in response.text
    assert "https://www.linkedin.com/in/abdulrazaq-adeyemi-b874103b1" in response.text
    assert "https://x.com/adexploit1" in response.text
    assert "https://wa.me/2349136168678" in response.text
    assert "application/ld+json" in response.text
    assert '"@type": "Person"' in response.text
    assert '"alternateName": ["Abdulrasaq Adeyemi"]' in response.text
    assert "Abdulrazaq Adeyemi is also sometimes written as Abdulrasaq Adeyemi." in response.text
    assert '"@type": "Organization"' in response.text
    assert '"@type": "WebSite"' in response.text
    assert 'rel="canonical"' in response.text
    assert 'property="og:image"' in response.text
    assert 'src="/assets/brand/adx-logo-dark.svg"' in response.text
    assert 'href="/static/css/style.css?v=4"' in response.text
    assert 'src="/assets/profile.jpg?v=2"' in response.text
    assert "signature-fallback" in response.text
    assert "initiative in development" in response.text
    assert 'property="og:url"' in response.text
    assert 'name="twitter:card"' in response.text


def test_required_assets_are_served():
    assert client.get("/assets/profile.jpg").status_code == 200
    for asset in ["adx-symbol.svg", "adx-logo-dark.svg", "adx-logo-light.svg", "adx-monochrome.svg", "adx-brand-preview.svg", "favicon.svg"]:
        assert client.get(f"/assets/brand/{asset}").status_code == 200


def test_contact_form_accepts_valid_message(monkeypatch):
    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            self.sent = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def login(self, username, password):
            assert username == "contact@adxgroup.tech"
            assert password == "test-password"

        def send_message(self, message):
            self.sent = True
            assert message["To"] == "contact@adxgroup.tech"
            assert message["Reply-To"] == "ada@example.com"

    monkeypatch.setenv("SMTP_PASSWORD", "test-password")
    monkeypatch.setattr("app.smtplib.SMTP_SSL", FakeSMTP)
    response = client.post(
        "/api/contact",
        json={"name": "Ada", "email": "ada@example.com", "scope": "Perimeter Audit", "message": "Hello"},
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_contact_form_rejects_invalid_email():
    response = client.post(
        "/api/contact",
        json={"name": "Ada", "email": "not-an-email", "scope": "Perimeter Audit", "message": "Hello"},
    )
    assert response.status_code == 422


def test_contact_form_rejects_invalid_scope():
    response = client.post(
        "/api/contact",
        json={"name": "Ada", "email": "ada@example.com", "scope": "Other", "message": "Hello"},
    )
    assert response.status_code == 422
