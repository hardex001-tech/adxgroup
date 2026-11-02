"""
ADX Group — OAuth Security & Authentication Regression Test Suite.
Validates the containment and remediation of the OAuth authentication bypass,
privilege escalation protections, server-side token verification, and session hygiene.
"""

import os
import sys
import time
import unittest
from unittest.mock import AsyncMock, patch

from starlette.testclient import TestClient

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import asgi_app
from core.auth import (
    _get_conn,
    create_or_login_oauth_user,
    decode_signed_token,
    init_db,
    OWNER_EMAILS,
)

client = TestClient(asgi_app)
TEST_CLIENT_ID = "test-adxgroup-google-client-id.apps.googleusercontent.com"


class MockHttpxResponse:
    """Mock httpx response for Google tokeninfo endpoint."""
    def __init__(self, status_code: int, data: dict):
        self.status_code = status_code
        self._data = data
        self.text = str(data)

    def json(self):
        return self._data


def run_all_oauth_tests():
    print("\n========================================================")
    print("RUNNING ADX GROUP OAUTH SECURITY REGRESSION TEST SUITE")
    print("========================================================")

    init_db()
    passed = 0
    total = 0

    # -----------------------------------------------------------------
    # Test 1: Arbitrary email in POST /api/auth/oauth without token rejected
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Arbitrary email without token is rejected (401)")
    arbitrary_email = "arbitrary.attacker.999@example.com"
    resp = client.post(
        "/api/auth/oauth",
        json={"email": arbitrary_email, "provider": "google", "name": "Attacker"},
    )
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
    assert "adx_session" not in resp.cookies, "Session cookie must not be set on failure"
    with _get_conn() as conn:
        user = conn.execute("SELECT id FROM users WHERE email = ?", (arbitrary_email,)).fetchone()
        assert user is None, "User record must not be created when token is missing"
    print("  PASS: Arbitrary email rejected with 401, no user or session created.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 2: Owner email claim without token rejected, no admin role
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Owner email claim without verified token rejected")
    for owner_email in OWNER_EMAILS:
        resp = client.post(
            "/api/auth/oauth",
            json={"email": owner_email, "provider": "google", "name": "Imposter"},
        )
        assert resp.status_code == 401, f"Expected 401 for owner {owner_email}, got {resp.status_code}"
        assert "adx_session" not in resp.cookies, "No session cookie on owner impersonation attempt"
    print("  PASS: All OWNER_EMAILS rejected with 401 without provider token.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 3: Missing, empty, or whitespace tokens rejected
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Missing, empty, or whitespace tokens rejected")
    for empty_tok in ["", "   ", None]:
        payload = {"provider": "google"}
        if empty_tok is not None:
            payload["id_token"] = empty_tok
        resp = client.post("/api/auth/oauth", json=payload)
        assert resp.status_code == 401, f"Expected 401 for empty token {empty_tok!r}, got {resp.status_code}"
        assert "adx_session" not in resp.cookies
    print("  PASS: Empty or whitespace tokens rejected with 401.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 4: Malformed or invalid signature token rejected by provider
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Malformed or invalid signature token rejected")
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = MockHttpxResponse(400, {"error_description": "Invalid Value"})
        resp = client.post(
            "/api/auth/oauth",
            json={"provider": "google", "id_token": "malformed.jwt.token"},
        )
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
        assert "adx_session" not in resp.cookies
    print("  PASS: Malformed/invalid token rejected with 401.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 5: Wrong audience / client ID token rejected
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Wrong audience (aud) token rejected")
    os.environ["GOOGLE_CLIENT_ID"] = TEST_CLIENT_ID
    try:
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            # Token signed by Google but issued for a different app/client ID
            mock_get.return_value = MockHttpxResponse(200, {
                "iss": "accounts.google.com",
                "aud": "attacker-unrelated-app.apps.googleusercontent.com",
                "sub": "sub-wrong-aud-12345",
                "email": "victim@example.com",
                "email_verified": "true",
                "exp": int(time.time()) + 3600,
            })
            resp = client.post(
                "/api/auth/oauth",
                json={"provider": "google", "id_token": "token.with.wrong.aud"},
            )
            assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
            assert "adx_session" not in resp.cookies
            assert "audience" in resp.text.lower() or "verification failed" in resp.text.lower()
    finally:
        os.environ.pop("GOOGLE_CLIENT_ID", None)
    print("  PASS: Token with mismatched audience rejected with 401.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 6: Untrusted issuer (iss) token rejected
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Untrusted issuer (iss) token rejected")
    os.environ["GOOGLE_CLIENT_ID"] = TEST_CLIENT_ID
    try:
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockHttpxResponse(200, {
                "iss": "https://untrusted-idp.attacker.com",
                "aud": TEST_CLIENT_ID,
                "sub": "sub-fake-iss-12345",
                "email": "victim@example.com",
                "email_verified": True,
                "exp": int(time.time()) + 3600,
            })
            resp = client.post(
                "/api/auth/oauth",
                json={"provider": "google", "id_token": "token.with.fake.iss"},
            )
            assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
            assert "adx_session" not in resp.cookies
    finally:
        os.environ.pop("GOOGLE_CLIENT_ID", None)
    print("  PASS: Untrusted token issuer rejected with 401.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 7: Expired token rejected
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Expired token rejected")
    os.environ["GOOGLE_CLIENT_ID"] = TEST_CLIENT_ID
    try:
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockHttpxResponse(200, {
                "iss": "https://accounts.google.com",
                "aud": TEST_CLIENT_ID,
                "sub": "sub-expired-12345",
                "email": "victim@example.com",
                "email_verified": True,
                "exp": int(time.time()) - 300,  # 5 minutes in the past
            })
            resp = client.post(
                "/api/auth/oauth",
                json={"provider": "google", "id_token": "token.expired"},
            )
            assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
            assert "adx_session" not in resp.cookies
    finally:
        os.environ.pop("GOOGLE_CLIENT_ID", None)
    print("  PASS: Expired token rejected with 401.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 8: Unverified email claim cannot authenticate or elevate
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Unverified email claim (email_verified=false) rejected")
    os.environ["GOOGLE_CLIENT_ID"] = TEST_CLIENT_ID
    unverified_claim_email = "unverified.owner@adxgroup.tech"
    try:
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockHttpxResponse(200, {
                "iss": "accounts.google.com",
                "aud": TEST_CLIENT_ID,
                "sub": "sub-unverified-email",
                "email": unverified_claim_email,
                "email_verified": False,
                "exp": int(time.time()) + 3600,
            })
            resp = client.post(
                "/api/auth/oauth",
                json={"provider": "google", "id_token": "token.unverified.email"},
            )
            assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
            assert "adx_session" not in resp.cookies
            with _get_conn() as conn:
                u = conn.execute("SELECT id FROM users WHERE email = ?", (unverified_claim_email,)).fetchone()
                assert u is None, "Account must not be created from unverified email claim"
    finally:
        os.environ.pop("GOOGLE_CLIENT_ID", None)
    print("  PASS: Unverified email claim rejected with 401, no account created.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 9: Failed authentication has zero side-effects
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Failed authentication side-effects test")
    with _get_conn() as conn:
        sessions_before = conn.execute("SELECT count(*) as c FROM sessions").fetchone()["c"]
    
    # Run multiple failed requests
    client.post("/api/auth/oauth", json={"email": "nobody@example.com"})
    client.post("/api/auth/oauth", json={"email": "admin@adxgroup.tech"})
    client.post("/api/auth/oauth", json={"id_token": "bad_token"})

    with _get_conn() as conn:
        sessions_after = conn.execute("SELECT count(*) as c FROM sessions").fetchone()["c"]
        assert sessions_after == sessions_before, "Failed auth must create NO sessions in database"
    print("  PASS: Zero session rows created on failed authentication attempts.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 10: Valid verified Google token for regular client succeeds
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Valid verified Google token for client succeeds and binds sub")
    os.environ["GOOGLE_CLIENT_ID"] = TEST_CLIENT_ID
    legit_email = f"verified.client.{int(time.time())}@company.com"
    legit_sub = f"google-sub-{int(time.time())}"
    try:
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockHttpxResponse(200, {
                "iss": "https://accounts.google.com",
                "aud": TEST_CLIENT_ID,
                "sub": legit_sub,
                "email": legit_email,
                "name": "Verified Client",
                "email_verified": True,
                "exp": int(time.time()) + 3600,
            })
            resp = client.post(
                "/api/auth/oauth",
                json={
                    "provider": "google",
                    "id_token": "valid.verified.token",
                    # Note: client-supplied email differs slightly, endpoint MUST use verified token email!
                    "email": "ignored_client_email@wrong.com",
                },
            )
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
            data = resp.json()
            assert data["ok"] is True
            assert data["user"]["email"] == legit_email, "Email must come from verified token, not client payload"
            assert data["user"]["role"] == "client", "Regular verified user must receive 'client' role"
            assert data["redirect"] == "/dashboard"
            assert "adx_session" in resp.cookies
            session_cookie = resp.cookies["adx_session"]
            decoded = decode_signed_token(session_cookie)
            assert decoded is not None and decoded["email"] == legit_email

            with _get_conn() as conn:
                row = conn.execute("SELECT * FROM users WHERE email = ?", (legit_email,)).fetchone()
                assert row is not None
                assert row["provider_sub"] == legit_sub, "Provider subject 'sub' must be securely bound in DB"
                assert row["email_verified"] == 1
    finally:
        os.environ.pop("GOOGLE_CLIENT_ID", None)
    print("  PASS: Valid verified client token logged in, sub bound, cookie set.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 11: Valid verified Google token for OWNER grants admin role
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Valid verified token for OWNER email grants admin role")
    os.environ["GOOGLE_CLIENT_ID"] = TEST_CLIENT_ID
    owner_test_email = "security@adxgroup.tech"
    owner_sub = "google-sub-verified-owner-007"
    try:
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockHttpxResponse(200, {
                "iss": "accounts.google.com",
                "aud": TEST_CLIENT_ID,
                "sub": owner_sub,
                "email": owner_test_email,
                "name": "Verified ADX Security Officer",
                "email_verified": True,
                "exp": int(time.time()) + 3600,
            })
            resp = client.post(
                "/api/auth/oauth",
                json={"provider": "google", "id_token": "valid.owner.token"},
            )
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
            data = resp.json()
            assert data["ok"] is True
            assert data["user"]["role"] == "admin", "Verified owner email must receive admin role"
            assert data["redirect"] == "/admin", "Admin must be redirected to /admin"
            assert "adx_session" in resp.cookies
    finally:
        os.environ.pop("GOOGLE_CLIENT_ID", None)
    print("  PASS: Cryptographically verified owner received admin role and /admin redirect.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 12: Provider subject mismatch prevents account hijacking
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Provider subject mismatch rejection (account takeover guard)")
    # legit_email was bound to legit_sub above. Now an attacker tries to authenticate
    # with a token claiming legit_email but with a different provider sub:
    try:
        create_or_login_oauth_user(
            email=legit_email,
            name="Imposter",
            provider="google",
            provider_sub="completely-different-sub-hijacker",
            email_verified=True,
        )
        assert False, "Should have raised ValueError due to provider_sub mismatch"
    except ValueError as err:
        assert "mismatch" in str(err).lower() or "identity" in str(err).lower()
    print("  PASS: Subject identity mismatch rejected, account hijacking prevented.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 13: Self-registration on /api/auth/register cannot grant admin
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Self-registration payload cannot grant admin role")
    target_owner = f"owner.test.{int(time.time())}@adxgroup.tech"
    OWNER_EMAILS.add(target_owner)
    try:
        resp = client.post(
            "/api/auth/register",
            json={
                "name": "Attacker Impersonator",
                "email": target_owner,
                "password": "Password123!",
                "company": "Fake Corp",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["role"] == "client", (
            f"VIOLATION: Registration granted role '{data['user']['role']}', must be 'client'!"
        )
        assert data["redirect"] == "/dashboard", "Must redirect to /dashboard, not /admin"
        with _get_conn() as conn:
            u = conn.execute("SELECT role, email_verified FROM users WHERE email = ?", (target_owner,)).fetchone()
            assert u["role"] == "client"
            assert u["email_verified"] == 0, "Registration must not be pre-verified"
    finally:
        OWNER_EMAILS.discard(target_owner)
    print("  PASS: Self-registration cannot grant admin role or bypass email verification.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 14: Owner password backdoor in /api/auth/login is completely removed
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] Insecure password override backdoor is eliminated")
    # abdulrasaqadeyemi12@gmail.com is in DB as admin (id: 1)
    with _get_conn() as conn:
        original_hash = conn.execute(
            "SELECT password_hash FROM users WHERE email = 'abdulrasaqadeyemi12@gmail.com'"
        ).fetchone()["password_hash"]

    resp = client.post(
        "/api/auth/login",
        json={
            "identifier": "abdulrasaqadeyemi12@gmail.com",
            "password": "WrongAttackerPassword999!",
        },
    )
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    assert "adx_session" not in resp.cookies

    with _get_conn() as conn:
        current_hash = conn.execute(
            "SELECT password_hash FROM users WHERE email = 'abdulrasaqadeyemi12@gmail.com'"
        ).fetchone()["password_hash"]
        assert current_hash == original_hash, (
            "CRITICAL: Stored password hash must NOT be overwritten on incorrect password attempt!"
        )
    print("  PASS: Owner password backdoor removed; hash unchanged, login rejected.")
    passed += 1

    # -----------------------------------------------------------------
    # Test 15: POST /api/auth/google/token also validates tokens securely
    # -----------------------------------------------------------------
    total += 1
    print(f"\n[TEST {total}] POST /api/auth/google/token enforces secure verification")
    # Empty credential rejected
    resp = client.post("/api/auth/google/token", json={"credential": ""})
    assert resp.status_code == 400
    # Invalid token rejected
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = MockHttpxResponse(400, {"error": "invalid_token"})
        resp = client.post("/api/auth/google/token", json={"credential": "invalid_gis_token"})
        assert resp.status_code == 401
    print("  PASS: POST /api/auth/google/token securely verifies tokens.")
    passed += 1

    print("\n========================================================")
    print(f"ALL {passed}/{total} OAUTH SECURITY REGRESSION TESTS PASSED PERFECTLY!")
    print("========================================================\n")


if __name__ == "__main__":
    run_all_oauth_tests()
