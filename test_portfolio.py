from starlette.testclient import TestClient

from app import asgi_app


client = TestClient(asgi_app)


def test_portfolio_home_is_simple_and_complete():
    response = client.get("/")
    assert response.status_code == 200
    assert "Small ideas." in response.text
    assert 'id="work"' in response.text
    assert 'id="about"' in response.text
    assert 'id="contact"' in response.text
    assert "ArmorLLM — AI Security Audit Engine" in response.text
    assert "https://github.com/hardex001-tech/JobHunter" in response.text
    assert "https://github.com/hardex001-tech/Sentinel-X" in response.text
    assert 'rel="canonical"' in response.text
    assert 'property="og:image"' in response.text
    assert 'src="/assets/profile.jpg"' in response.text
    assert "https://www.linkedin.com/in/abdulrazaq-adeyemi-b874103b1" in response.text


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
        json={"name": "Ada", "email": "ada@example.com", "message": "Hello"},
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_contact_form_rejects_invalid_email():
    response = client.post(
        "/api/contact",
        json={"name": "Ada", "email": "not-an-email", "message": "Hello"},
    )
    assert response.status_code == 422
