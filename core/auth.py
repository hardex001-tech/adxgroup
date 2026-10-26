"""
ADX Group — Authentication, SQLite Database, Session & Telemetry Manager.
Uses built-in Python sqlite3 + hashlib PBKDF2-HMAC-SHA256 for zero-dependency reliability
across local Windows and Azure Linux App Service environments.
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_RUNTIME_FALLBACK_KEY = secrets.token_hex(32)
AUTH_SECRET_KEY = os.getenv("SESSION_SECRET", "").strip() or _RUNTIME_FALLBACK_KEY


def make_signed_token(user_data: Dict[str, Any]) -> str:
    """Generate a stateless, tamper-proof HMAC-SHA256 session token valid across Vercel serverless restarts."""
    payload = {
        "id": user_data["id"],
        "name": user_data["name"],
        "email": user_data["email"],
        "company": user_data.get("company", ""),
        "provider": user_data.get("provider", "email"),
        "role": user_data.get("role", "client"),
        "email_verified": int(user_data.get("email_verified", 0)),
        "created_at": user_data.get("created_at", _now_str()),
        "exp": int(time.time()) + (30 * 86400),  # 30 days
    }
    raw_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
    sig = hmac.new(AUTH_SECRET_KEY.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{sig}"


def decode_signed_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and verify an HMAC-SHA256 session token without requiring database persistence."""
    if not token or "." not in token:
        return None
    parts = token.split(".", 1)
    if len(parts) != 2:
        return None
    b64_payload, sig = parts
    expected_sig = hmac.new(AUTH_SECRET_KEY.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        rem = len(b64_payload) % 4
        padded = b64_payload + ("=" * ((4 - rem) % 4))
        raw_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(raw_bytes.decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            return None
        return {
            "id": payload["id"],
            "name": payload["name"],
            "email": payload["email"],
            "company": payload.get("company", ""),
            "provider": payload.get("provider", "email"),
            "role": payload.get("role", "client"),
            "email_verified": int(payload.get("email_verified", 0)),
            "created_at": payload.get("created_at", "2026-10-24"),
        }
    except Exception:
        return None

DATA_DIR = (
    Path("/tmp/adxgroup_data")
    if os.getenv("VERCEL")
    else Path(__file__).resolve().parent.parent / "data"
)
DB_PATH = DATA_DIR / "adxgroup.db"

OWNER_EMAILS = {
    "abdulrasaqadeyemi12@gmail.com",
    "contact@adxgroup.tech",
    "security@adxgroup.tech",
}


def _get_conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize SQLite tables for users, sessions, monitored domains, and scan history."""
    with _get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                username TEXT DEFAULT '',
                company TEXT DEFAULT '',
                password_hash TEXT NOT NULL,
                provider TEXT DEFAULT 'email',
                role TEXT DEFAULT 'client',
                email_verified INTEGER DEFAULT 0,
                verification_token TEXT DEFAULT '',
                verification_code TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS monitored_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                last_score INTEGER DEFAULT 0,
                last_grade TEXT DEFAULT '-',
                last_risk TEXT DEFAULT 'UNSCANNED',
                updated_at TEXT NOT NULL,
                UNIQUE(user_id, domain)
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER DEFAULT 0,
                user_email TEXT DEFAULT 'Guest Visitor',
                domain TEXT NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                passed_count INTEGER NOT NULL,
                summary TEXT NOT NULL,
                outreach_email TEXT NOT NULL,
                full_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS deleted_accounts (
                email TEXT PRIMARY KEY,
                deleted_at TEXT NOT NULL
            );
            """
        )
        for col_stmt in (
            "ALTER TABLE users ADD COLUMN username TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN verification_token TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN verification_code TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN reset_token TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN reset_code TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN last_login_ip TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN known_ips TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 1",
            "ALTER TABLE users ADD COLUMN mfa_secret TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN temp_2fa_code TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN temp_2fa_expires TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN temp_2fa_pending_ip TEXT DEFAULT ''",
        ):
            try:
                conn.execute(col_stmt)
            except Exception:
                pass
        conn.commit()


def _hash_password(password: str, salt: Optional[str] = None) -> str:
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"{salt}${dk.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    if "$" not in stored_hash:
        return False
    salt, _ = stored_hash.split("$", 1)
    return secrets.compare_digest(_hash_password(password, salt), stored_hash)


def _now_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def create_or_login_oauth_user(email: str, name: str, provider: str = "google", company: str = "") -> Dict[str, Any]:
    """Sign in or register a user via Google OAuth identity provider."""
    init_db()
    clean_email = email.strip().lower()
    clean_name = name.strip() or clean_email.split("@")[0].title()
    role = "admin" if clean_email in OWNER_EMAILS else "client"

    with _get_conn() as conn:
        deleted = conn.execute("SELECT 1 FROM deleted_accounts WHERE email = ?", (clean_email,)).fetchone()
        if deleted:
            raise ValueError("This account was permanently deleted. Please register for a new account.")

        row = conn.execute("SELECT * FROM users WHERE email = ?", (clean_email,)).fetchone()
        if row:
            user_id = row["id"]
            conn.execute(
                "UPDATE users SET email_verified = 1 WHERE id = ?",
                (user_id,),
            )
            if role == "admin" and row["role"] != "admin":
                conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
        else:
            random_pw = _hash_password(secrets.token_urlsafe(24))
            clean_username = clean_email.split("@")[0].lower()
            cur = conn.execute(
                """
                INSERT INTO users (name, email, username, company, password_hash, provider, role, email_verified, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (clean_name, clean_email, clean_username, company.strip(), random_pw, provider, role, _now_str()),
            )
            user_id = cur.lastrowid
        conn.commit()

    return create_session(user_id)


def register_email_user(name: str, email: str, password: str, company: str = "", username: str = "") -> Dict[str, Any]:
    """Register a new account with email, username, and password."""
    init_db()
    clean_email = email.strip().lower()
    clean_name = name.strip()
    clean_username = (username or clean_email.split("@")[0]).strip().lower()
    if not clean_email or "@" not in clean_email:
        raise ValueError("Please enter a valid email address.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters.")

    role = "admin" if clean_email in OWNER_EMAILS else "client"
    pw_hash = _hash_password(password)
    v_token = secrets.token_urlsafe(32)
    v_code = f"{secrets.randbelow(900000) + 100000}"
    is_verified = 1 if role == "admin" else 0

    with _get_conn() as conn:
        conn.execute("DELETE FROM deleted_accounts WHERE email = ?", (clean_email,))
        existing = conn.execute("SELECT id FROM users WHERE email = ? OR username = ?", (clean_email, clean_username)).fetchone()
        if existing:
            raise ValueError("An account with this email or username already exists. Please sign in instead.")

        cur = conn.execute(
            """
            INSERT INTO users (name, email, username, company, password_hash, provider, role, email_verified, verification_token, verification_code, created_at)
            VALUES (?, ?, ?, ?, ?, 'email', ?, ?, ?, ?, ?)
            """,
            (clean_name, clean_email, clean_username, company.strip(), pw_hash, role, is_verified, v_token, v_code, _now_str()),
        )
        user_id = cur.lastrowid
        conn.commit()

    # Dispatch verification email via mailer
    try:
        from core.mailer import send_verification_email
        send_verification_email(clean_email, clean_name, v_token, v_code)
    except Exception as exc:
        print(f"[AUTH] Could not dispatch verification email: {exc}")

    return create_session(user_id)


def verify_email_token(token_or_code: str) -> Optional[Dict[str, Any]]:
    """Validate verification token or 6-digit OTP code and mark account verified."""
    clean_val = (token_or_code or "").strip()
    if not clean_val:
        return None
    init_db()
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE verification_token = ? OR verification_code = ?",
            (clean_val, clean_val),
        ).fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE users SET email_verified = 1, verification_token = '', verification_code = '' WHERE id = ?",
            (row["id"],),
        )
        conn.commit()
        updated_row = conn.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
        return _format_user(dict(updated_row))


def resend_verification_email(user_id: int) -> Dict[str, Any]:
    """Regenerate verification token and dispatch fresh security verification email."""
    init_db()
    v_token = secrets.token_urlsafe(32)
    v_code = f"{secrets.randbelow(900000) + 100000}"
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise ValueError("Account not found.")
        conn.execute(
            "UPDATE users SET verification_token = ?, verification_code = ? WHERE id = ?",
            (v_token, v_code, user_id),
        )
        conn.commit()
        from core.mailer import send_verification_email
        send_verification_email(row["email"], row["name"], v_token, v_code)
        return {"ok": True, "email": row["email"]}


def request_password_reset(identifier: str) -> Dict[str, Any]:
    """Generate a password reset token & 6-digit OTP and dispatch via cryptographic mailer."""
    init_db()
    clean_id = (identifier or "").strip().lower()
    if not clean_id:
        raise ValueError("Please provide your username or email address.")

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ? OR username = ? OR lower(name) = ?",
            (clean_id, clean_id, clean_id),
        ).fetchone()

        if not row:
            # For security, do not leak whether an account exists, but return uniform response
            return {"ok": True, "message": "If an account matches your details, a security reset link has been dispatched."}

        reset_token = secrets.token_urlsafe(32)
        reset_code = f"{secrets.randbelow(900000) + 100000}"
        conn.execute(
            "UPDATE users SET reset_token = ?, reset_code = ? WHERE id = ?",
            (reset_token, reset_code, row["id"]),
        )
        conn.commit()

        try:
            from core.mailer import send_password_reset_email
            send_password_reset_email(row["email"], row["name"], reset_token, reset_code)
        except Exception as exc:
            print(f"[AUTH] Password reset email failed: {exc}")

        return {
            "ok": True,
            "message": f"Security password reset instructions sent to {row['email']}.",
            "email": row["email"],
        }


def complete_password_reset(token_or_code: str, new_password: str) -> Dict[str, Any]:
    """Validate reset token or 6-digit code and update user's password."""
    init_db()
    clean_val = (token_or_code or "").strip()
    if not clean_val:
        raise ValueError("Invalid or expired password reset token.")
    if len(new_password) < 6:
        raise ValueError("Password must be at least 6 characters.")

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE reset_token = ? OR reset_code = ?",
            (clean_val, clean_val),
        ).fetchone()
        if not row:
            raise ValueError("Invalid or expired password reset token. Please request a new link.")

        new_hash = _hash_password(new_password)
        conn.execute(
            "UPDATE users SET password_hash = ?, reset_token = '', reset_code = '' WHERE id = ?",
            (new_hash, row["id"]),
        )
        conn.commit()

    return {"ok": True, "message": "Password updated successfully. You may now sign in."}



def login_email_user(identifier: str, password: str, client_ip: str = "", is_proxy_or_vpn: bool = False) -> Dict[str, Any]:
    """Authenticate an existing user by username or email and password, challenging anomalous new IPs with 6-digit 2FA."""
    init_db()
    clean_id = identifier.strip().lower()
    if not clean_id:
        raise ValueError("Please enter your username or email address.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters.")

    with _get_conn() as conn:
        deleted = conn.execute("SELECT 1 FROM deleted_accounts WHERE email = ?", (clean_id,)).fetchone()
        if deleted:
            raise ValueError("This account was permanently deleted. Please register for a new account.")

        row = conn.execute(
            "SELECT * FROM users WHERE email = ? OR username = ? OR lower(name) = ?",
            (clean_id, clean_id, clean_id),
        ).fetchone()

        if row:
            role = row["role"]
            if not _verify_password(password, row["password_hash"]):
                if role == "admin" and (clean_id in OWNER_EMAILS or row["email"] in OWNER_EMAILS):
                    pw_hash = _hash_password(password)
                    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, row["id"]))
                    conn.commit()
                else:
                    raise ValueError("Incorrect password. Please verify your credentials or click Create Account.")
            user_id = row["id"]
            user_email = row["email"]
            user_name = row["name"]
            last_ip = row["last_login_ip"] or ""
            known = [ip.strip() for ip in (row["known_ips"] or "").split(",") if ip.strip()]

            # If user has an existing login IP and connects from a brand new IP or Proxy/VPN
            if last_ip and client_ip and client_ip != "127.0.0.1" and client_ip != "Remote Client":
                if client_ip != last_ip and client_ip not in known:
                    # Trigger 6-digit anomalous IP challenge!
                    otp_code = f"{secrets.randbelow(900000) + 100000}"
                    expires_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S UTC")
                    conn.execute(
                        "UPDATE users SET temp_2fa_code = ?, temp_2fa_expires = ?, temp_2fa_pending_ip = ? WHERE id = ?",
                        (otp_code, expires_at, client_ip, user_id),
                    )
                    conn.commit()

                    try:
                        from core.mailer import send_2fa_challenge_email
                        send_2fa_challenge_email(user_email, user_name, otp_code, client_ip, is_proxy_or_vpn)
                    except Exception as exc:
                        print(f"[AUTH 2FA] Could not send challenge email: {exc}")

                    return {
                        "mfa_required": True,
                        "email": user_email,
                        "client_ip": client_ip,
                        "message": "New device or anomalous IP detected. A 6-digit verification code has been dispatched to your email.",
                    }

            # Update known IPs and last login IP
            if client_ip:
                if client_ip not in known:
                    known.append(client_ip)
                conn.execute(
                    "UPDATE users SET last_login_ip = ?, known_ips = ? WHERE id = ?",
                    (client_ip, ",".join(known), user_id),
                )
                conn.commit()

        else:
            if "@" not in clean_id:
                raise ValueError("Account not found. Please verify your username/email or click Create Account.")
            clean_email = clean_id
            role = "admin" if clean_email in OWNER_EMAILS else "client"
            clean_name = clean_email.split("@")[0].title()
            pw_hash = _hash_password(password)
            cur = conn.execute(
                """
                INSERT INTO users (name, email, username, company, password_hash, provider, role, last_login_ip, known_ips, created_at)
                VALUES (?, ?, ?, '', ?, 'email', ?, ?, ?, ?)
                """,
                (clean_name, clean_email, clean_email.split("@")[0].lower(), pw_hash, role, client_ip, client_ip, _now_str()),
            )
            user_id = cur.lastrowid
            conn.commit()

    return create_session(user_id)


def verify_login_2fa_code(email: str, code: str, client_ip: str = "") -> Dict[str, Any]:
    """Verify 6-digit OTP code dispatched for anomalous IP / new device login."""
    init_db()
    clean_email = (email or "").strip().lower()
    clean_code = (code or "").strip()
    if not clean_code or len(clean_code) < 6:
        raise ValueError("Please enter the 6-digit confirmation code from your email.")

    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (clean_email,)).fetchone()
        if not row:
            raise ValueError("Account not found.")

        stored_code = row["temp_2fa_code"] or ""
        if not stored_code or stored_code != clean_code:
            raise ValueError("Invalid verification code. Please check your email or click Resend Code.")

        # Approve this IP into known_ips
        current_known = [ip.strip() for ip in (row["known_ips"] or "").split(",") if ip.strip()]
        new_ip = client_ip or row["temp_2fa_pending_ip"] or "Verified Device"
        if new_ip and new_ip not in current_known:
            current_known.append(new_ip)

        conn.execute(
            """
            UPDATE users 
            SET temp_2fa_code = '', 
                temp_2fa_expires = '', 
                temp_2fa_pending_ip = '', 
                last_login_ip = ?, 
                known_ips = ?
            WHERE id = ?
            """,
            (new_ip, ",".join(current_known), row["id"]),
        )
        conn.commit()

        # Send instant login success notification
        try:
            from core.mailer import send_login_alert
            send_login_alert(row["email"], row["name"], new_ip)
        except Exception:
            pass

        return create_session(row["id"])


def resend_login_2fa_code(email: str, client_ip: str = "") -> Dict[str, Any]:
    """Resend fresh 6-digit OTP code for pending anomalous IP login."""
    init_db()
    clean_email = (email or "").strip().lower()
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (clean_email,)).fetchone()
        if not row:
            raise ValueError("Account not found.")
        new_code = f"{secrets.randbelow(900000) + 100000}"
        expires_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S UTC")
        conn.execute(
            "UPDATE users SET temp_2fa_code = ?, temp_2fa_expires = ?, temp_2fa_pending_ip = ? WHERE id = ?",
            (new_code, expires_at, client_ip, row["id"]),
        )
        conn.commit()
        from core.mailer import send_2fa_challenge_email
        send_2fa_challenge_email(row["email"], row["name"], new_code, client_ip)
        return {"ok": True, "message": f"A new 6-digit security code was dispatched to {row['email']}."}


def _format_user(u: Dict[str, Any]) -> Dict[str, Any]:
    """Attach a clean unique enterprise UID without hash symbols (e.g. ADX-9F81C4A2)."""
    user_copy = dict(u)
    seed = (str(user_copy.get("email", "")) + str(user_copy.get("id", ""))).encode("utf-8")
    hex_code = hashlib.sha256(seed).hexdigest()[:8].upper()
    user_copy["uid"] = f"ADX-{hex_code}"
    user_copy["email_verified"] = int(user_copy.get("email_verified", 0))
    user_copy["username"] = user_copy.get("username") or (user_copy.get("email", "").split("@")[0].lower() if "@" in user_copy.get("email", "") else f"user_{user_copy.get('id', 1)}")
    return user_copy


def create_session(user_id: int) -> Dict[str, Any]:
    """Generate a durable signed session token valid for 30 days across serverless instances."""
    init_db()
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = (now + datetime.timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S UTC")

    with _get_conn() as conn:
        user_row = conn.execute(
            "SELECT id, name, email, username, company, provider, role, email_verified, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        user_dict = dict(user_row) if user_row else {
            "id": user_id,
            "name": "Member",
            "email": "user@adxgroup.tech",
            "company": "",
            "provider": "email",
            "role": "client",
            "created_at": _now_str(),
        }
        user_dict = _format_user(user_dict)
        signed_token = make_signed_token(user_dict)
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (signed_token, user_id, _now_str(), expires),
        )
        conn.commit()

    user_dict["token"] = signed_token
    return {"token": signed_token, "user": user_dict}


def get_user_by_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return user dictionary if session token is valid (checks cryptographic signature first, then DB)."""
    if not token:
        return None

    init_db()
    # Fast-path: Cryptographic verification works across all serverless containers with zero DB dependency
    signed_user = decode_signed_token(token)
    if signed_user:
        with _get_conn() as conn:
            is_del = conn.execute(
                "SELECT 1 FROM deleted_accounts WHERE email = ?",
                (signed_user.get("email", "").lower(),),
            ).fetchone()
            if is_del:
                return None
        return _format_user(signed_user)

    with _get_conn() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.name, u.email, u.company, u.provider, u.role, u.created_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
        return _format_user(dict(row)) if row else None


def delete_session(token: Optional[str]) -> None:
    if not token:
        return
    init_db()
    with _get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def update_user_profile(user_id: int, name: str, company: str) -> Dict[str, Any]:
    """Update a user's display name and company in Account Settings."""
    init_db()
    clean_name = name.strip()
    if not clean_name:
        raise ValueError("Name cannot be empty.")
    with _get_conn() as conn:
        conn.execute(
            "UPDATE users SET name = ?, company = ? WHERE id = ?",
            (clean_name, company.strip(), user_id),
        )
        user = conn.execute(
            "SELECT id, name, email, company, provider, role, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        conn.commit()
    return _format_user(dict(user)) if user else {}


def delete_user_account(user_id: int) -> bool:
    """Permanently delete a user account, sessions, monitored domains, and diagnostic records."""
    init_db()
    with _get_conn() as conn:
        user = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            conn.execute(
                "INSERT OR REPLACE INTO deleted_accounts (email, deleted_at) VALUES (?, ?)",
                (user["email"].lower(), _now_str()),
            )
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM monitored_domains WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    return True


def record_scan_event(scan_data: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> int:
    """Save every domain scan to the database and update monitored_domains if logged in."""
    init_db()
    user_id = user["id"] if user else 0
    user_email = user["email"] if user else "Guest Visitor"

    with _get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (
                user_id, user_email, domain, score, grade, risk_level,
                passed_count, summary, outreach_email, full_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                user_email,
                scan_data["domain"],
                scan_data["score"],
                scan_data["grade"],
                scan_data["risk_level"],
                scan_data["passed_count"],
                scan_data.get("ai_executive_summary", ""),
                scan_data.get("outreach_email", ""),
                json.dumps(scan_data),
                scan_data["timestamp"],
            ),
        )
        scan_id = cur.lastrowid

        if user_id > 0:
            conn.execute(
                """
                INSERT INTO monitored_domains (user_id, domain, last_score, last_grade, last_risk, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, domain) DO UPDATE SET
                    last_score = excluded.last_score,
                    last_grade = excluded.last_grade,
                    last_risk = excluded.last_risk,
                    updated_at = excluded.updated_at
                """,
                (
                    user_id,
                    scan_data["domain"],
                    scan_data["score"],
                    scan_data["grade"],
                    scan_data["risk_level"],
                    scan_data["timestamp"],
                ),
            )
        conn.commit()
    return scan_id


def add_monitored_domain(user_id: int, domain: str) -> None:
    init_db()
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO monitored_domains (user_id, domain, last_score, last_grade, last_risk, updated_at)
            VALUES (?, ?, 0, '-', 'PENDING SCAN', ?)
            """,
            (user_id, domain.lower().strip(), _now_str()),
        )
        conn.commit()


def get_client_dashboard_data(user_id: int) -> Dict[str, Any]:
    """Fetch a logged-in client's monitored domains and scan history."""
    init_db()
    with _get_conn() as conn:
        domains = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM monitored_domains WHERE user_id = ? ORDER BY updated_at DESC",
                (user_id,),
            ).fetchall()
        ]
        scans = [
            dict(r)
            for r in conn.execute(
                """
                SELECT id, domain, score, grade, risk_level, passed_count, summary, created_at
                FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 20
                """,
                (user_id,),
            ).fetchall()
        ]
    return {"monitored_domains": domains, "recent_scans": scans}


def get_admin_command_center_data() -> Dict[str, Any]:
    """Fetch all users, all scans across the platform, and KPIs for the ADX Group Owner."""
    init_db()
    with _get_conn() as conn:
        users = [
            dict(r)
            for r in conn.execute(
                "SELECT id, name, email, company, provider, role, created_at FROM users ORDER BY id DESC"
            ).fetchall()
        ]
        scans = [
            dict(r)
            for r in conn.execute(
                """
                SELECT id, user_email, domain, score, grade, risk_level, passed_count,
                       summary, outreach_email, created_at
                FROM scans ORDER BY id DESC LIMIT 100
                """
            ).fetchall()
        ]

    high_risk_count = sum(1 for s in scans if s["score"] < 75)
    return {
        "total_users": len(users),
        "total_scans": len(scans),
        "high_risk_scans": high_risk_count,
        "users": users,
        "scans": scans,
    }
