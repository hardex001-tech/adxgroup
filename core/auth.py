"""
ADX Group — Authentication, SQLite Database, Session & Telemetry Manager.
Uses built-in Python sqlite3 + hashlib PBKDF2-HMAC-SHA256 for zero-dependency reliability
across local Windows and Azure Linux App Service environments.
"""

import datetime
import hashlib
import json
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "adxgroup.db"

OWNER_EMAILS = {
    "abdulrasaqadeyemi12@gmail.com",
    "hardexmarley340@gmail.com",
    "abdulrazaqaa.25@student.funaab.edu.ng",
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
    """Authenticate an existing email/password user."""
    init_db()
    clean_email = email.strip().lower()
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (clean_email,)).fetchone()
        if not row or not _verify_password(password, row["password_hash"]):
            raise ValueError("Invalid email or password.")
        user_id = row["id"]

    return create_session(user_id)


def create_session(user_id: int) -> Dict[str, Any]:
    """Generate a session token valid for 14 days."""
    init_db()
    token = secrets.token_urlsafe(36)
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = (now + datetime.timedelta(days=14)).strftime("%Y-%m-%d %H:%M:%S UTC")

    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, _now_str(), expires),
        )
        user = conn.execute(
            "SELECT id, name, email, company, provider, role, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        conn.commit()

    return {"token": token, "user": dict(user)}


def get_user_by_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return user dictionary if session token is valid."""
    if not token:
        return None
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
        return dict(row) if row else None


def delete_session(token: Optional[str]) -> None:
    if not token:
        return
    init_db()
    with _get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


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
