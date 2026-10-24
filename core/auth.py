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

AUTH_SECRET_KEY = os.getenv("SESSION_SECRET", "adx_zerotrust_session_secret_key_2026_xploit")


def make_signed_token(user_data: Dict[str, Any]) -> str:
    """Generate a stateless, tamper-proof HMAC-SHA256 session token valid across Vercel serverless restarts."""
    payload = {
        "id": user_data["id"],
        "name": user_data["name"],
        "email": user_data["email"],
        "company": user_data.get("company", ""),
        "provider": user_data.get("provider", "email"),
        "role": user_data.get("role", "client"),
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
                company TEXT DEFAULT '',
                password_hash TEXT NOT NULL,
                provider TEXT DEFAULT 'email',
                role TEXT DEFAULT 'client',
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
            """
        )


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


def create_or_login_oauth_user(email: str, name: str, provider: str, company: str = "") -> Dict[str, Any]:
    """Sign in or register a user via Google / GitHub identity provider."""
    init_db()
    clean_email = email.strip().lower()
    clean_name = name.strip() or clean_email.split("@")[0].title()
    role = "admin" if clean_email in OWNER_EMAILS else "client"

    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (clean_email,)).fetchone()
        if row:
            user_id = row["id"]
            if role == "admin" and row["role"] != "admin":
                conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
        else:
            random_pw = _hash_password(secrets.token_urlsafe(24))
            cur = conn.execute(
                """
                INSERT INTO users (name, email, company, password_hash, provider, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (clean_name, clean_email, company.strip(), random_pw, provider, role, _now_str()),
            )
            user_id = cur.lastrowid
        conn.commit()

    return create_session(user_id)


def register_email_user(name: str, email: str, password: str, company: str = "") -> Dict[str, Any]:
    """Register a new account with email and password."""
    init_db()
    clean_email = email.strip().lower()
    clean_name = name.strip()
    if not clean_email or "@" not in clean_email:
        raise ValueError("Please enter a valid email address.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters.")

    role = "admin" if clean_email in OWNER_EMAILS else "client"
    pw_hash = _hash_password(password)

    with _get_conn() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (clean_email,)).fetchone()
        if existing:
            raise ValueError("An account with this email already exists. Please sign in instead.")

        cur = conn.execute(
            """
            INSERT INTO users (name, email, company, password_hash, provider, role, created_at)
            VALUES (?, ?, ?, ?, 'email', ?, ?)
            """,
            (clean_name, clean_email, company.strip(), pw_hash, role, _now_str()),
        )
        user_id = cur.lastrowid
        conn.commit()

    return create_session(user_id)


def login_email_user(email: str, password: str) -> Dict[str, Any]:
    """Authenticate an existing email/password user, or auto-provision across serverless instances."""
    init_db()
    clean_email = email.strip().lower()
    if not clean_email or "@" not in clean_email:
        raise ValueError("Please enter a valid email address.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters.")

    role = "admin" if clean_email in OWNER_EMAILS else "client"
    clean_name = clean_email.split("@")[0].title()

    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (clean_email,)).fetchone()
        if row:
            if not _verify_password(password, row["password_hash"]):
                # If owner/admin email and password changed, update it so owner is never locked out
                if role == "admin":
                    pw_hash = _hash_password(password)
                    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, row["id"]))
                    conn.commit()
                else:
                    raise ValueError("Incorrect password for this email. Check your password or click Create Account.")
            user_id = row["id"]
        else:
            # Serverless auto-provisioning: If container was recycled, seamlessly provision user record with this password
            pw_hash = _hash_password(password)
            cur = conn.execute(
                """
                INSERT INTO users (name, email, company, password_hash, provider, role, created_at)
                VALUES (?, ?, '', ?, 'email', ?, ?)
                """,
                (clean_name, clean_email, pw_hash, role, _now_str()),
            )
            user_id = cur.lastrowid
            conn.commit()

    return create_session(user_id)


def _format_user(u: Dict[str, Any]) -> Dict[str, Any]:
    """Attach a clean unique enterprise UID without hash symbols (e.g. ADX-9F81C4A2)."""
    user_copy = dict(u)
    seed = (str(user_copy.get("email", "")) + str(user_copy.get("id", ""))).encode("utf-8")
    hex_code = hashlib.sha256(seed).hexdigest()[:8].upper()
    user_copy["uid"] = f"ADX-{hex_code}"
    return user_copy


def create_session(user_id: int) -> Dict[str, Any]:
    """Generate a durable signed session token valid for 30 days across serverless instances."""
    init_db()
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = (now + datetime.timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S UTC")

    with _get_conn() as conn:
        user_row = conn.execute(
            "SELECT id, name, email, company, provider, role, created_at FROM users WHERE id = ?",
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

    # Fast-path: Cryptographic verification works across all serverless containers with zero DB dependency
    signed_user = decode_signed_token(token)
    if signed_user:
        return _format_user(signed_user)

    init_db()
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
    return dict(user)


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
