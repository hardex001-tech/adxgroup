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
    assert "StudyFlow" in response.text


def test_contact_form_accepts_valid_message():
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
