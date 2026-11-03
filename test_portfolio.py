from starlette.testclient import TestClient

from app import asgi_app


client = TestClient(asgi_app)


def test_portfolio_home_is_simple_and_complete():
    response = client.get("/")
    assert response.status_code == 200
    assert "Offensive Research.<br><em>Automated Defense.</em>" in response.text
    assert "Abdulrazaq Adeyemi" in response.text
    assert "Founder, ADX Group" in response.text
    assert "Domain &amp; Email Armor" in response.text
    assert 'id="projects"' in response.text
    assert 'id="guild"' in response.text
    assert 'id="contact"' in response.text
    assert "🛡️ S3 Shield Defense" in response.text
    assert "⚡ NetGuard Scanner" in response.text
    assert "🎯 Canary Deception Trap" in response.text
    assert "🔐 SQLi Exploitation Lab" in response.text
    assert "https://github.com/hardex001-tech/S3-Shield-Protocol-Defense-Lab" in response.text
    assert "https://github.com/hardex001-tech/netguard-scanner" in response.text
    assert "https://github.com/hardex001-tech/Canary-Poison-Deception-Trap" in response.text
    assert "https://github.com/hardex001-tech/sql-injection-payroll-lab" in response.text
    assert 'name="scope"' in response.text
    assert "Lead Defensive Engineer" not in response.text
    assert "SC-900" not in response.text
    assert "Builder of ADX" not in response.text
    assert "SURFACE SCAN" not in response.text
    assert "Security operations" in response.text
    assert "The security arsenal" in response.text
    assert "Direct dispatch" in response.text
    assert 'rel="canonical"' in response.text
    assert 'property="og:image"' in response.text
    assert 'src="/assets/brand/logo-lockup.svg"' in response.text
    assert 'href="/static/css/style.css?v=2"' in response.text
    assert 'src="/assets/profile.jpg?v=2"' in response.text
    assert 'property="og:url"' in response.text
    assert 'name="twitter:card"' in response.text


def test_required_assets_are_served():
    assert client.get("/assets/profile.jpg").status_code == 200
    assert client.get("/assets/brand/logo-lockup.svg").status_code == 200


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
