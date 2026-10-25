"""
ADX Group — Enterprise Cryptographic Email Dispatcher & Security Verification Hub.
Handles:
1. Account verification tokens & 6-digit OTP codes for new sign-ups.
2. Sign-in security alerts and new-device perimeter notices.
3. Client lead dispatching to contact@adxgroup.tech.
Connects to Zoho Mail SMTP (smtp.zoho.com / smtppro.zoho.com) with resilient outbox fallback.
"""

import datetime
import json
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_DIR = (
    Path("/tmp/adxgroup_data")
    if os.getenv("VERCEL")
    else Path(__file__).resolve().parent.parent / "data"
)
OUTBOX_FILE = DATA_DIR / "outbox.json"

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.zoho.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER = os.getenv("SMTP_USER", "contact@adxgroup.tech")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", f"ADX Group Security <{SMTP_USER}>")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://adxgroup.tech")


def _ensure_outbox() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not OUTBOX_FILE.exists():
        OUTBOX_FILE.write_text("[]", encoding="utf-8")


def get_outbox() -> List[Dict[str, Any]]:
    """Return all dispatched or queued security emails for the Owner Admin Console."""
    _ensure_outbox()
    try:
        return json.loads(OUTBOX_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _record_to_outbox(entry: Dict[str, Any]) -> None:
    _ensure_outbox()
    try:
        items = get_outbox()
        items.insert(0, entry)
        OUTBOX_FILE.write_text(json.dumps(items[:200], indent=2), encoding="utf-8")
    except Exception:
        pass


def _send_smtp_email(to_email: str, subject: str, html_body: str, text_body: str) -> bool:
    """Send live email via Zoho Mail SMTP if credentials exist."""
    if not SMTP_PASSWORD:
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, [to_email], msg.as_string())
        return True
    except Exception as exc:
        print(f"[ADX MAILER] SMTP dispatch failed: {exc}")
        return False


def send_verification_email(email: str, name: str, token: str, code: str) -> Dict[str, Any]:
    """Send security verification email with 6-digit OTP and instant verification link."""
    clean_email = email.strip().lower()
    clean_name = name.strip() or clean_email.split("@")[0].title()
    verify_url = f"{APP_BASE_URL}/api/auth/verify?token={token}"

    subject = f"Verify Your ADX Group Security Console Account ({code})"

    text_body = f"""Hello {clean_name},

Welcome to ADX Group (adxgroup.tech).

Please verify your email address to activate your zero-trust security console:
Your Security Verification Code is: {code}

Or confirm your account directly by visiting:
{verify_url}

This verification link expires in 24 hours.

If you did not register for an ADX account, please disregard this email.

Best regards,
ADX Cyber Systems Engineering
contact@adxgroup.tech | https://adxgroup.tech
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Verify Your ADX Group Account</title>
</head>
<body style="margin: 0; padding: 24px 0; background-color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #0f172a;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table width="560" border="0" cellspacing="0" cellpadding="0" style="background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(15,23,42,0.06);">
          <tr>
            <td style="background: #0f172a; padding: 24px 32px; border-bottom: 2px solid #2563eb;">
              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <span style="color: #ffffff; font-size: 18px; font-weight: 800; letter-spacing: -0.3px;">ADX GROUP</span>
                    <span style="display: block; color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; margin-top: 2px;">Silent Innovation. Absolute Defense.</span>
                  </td>
                  <td align="right">
                    <span style="background: rgba(37,99,235,0.25); color: #60a5fa; border: 1px solid rgba(96,165,250,0.3); padding: 4px 10px; border-radius: 4px; font-size: 10.5px; font-family: monospace; font-weight: 700;">IDENTITY GATE</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding: 32px;">
              <h1 style="margin: 0 0 12px 0; font-size: 20px; font-weight: 800; color: #0f172a;">Verify Your Account</h1>
              <p style="margin: 0 0 20px 0; font-size: 14px; line-height: 1.6; color: #475569;">
                Hello <strong>{clean_name}</strong>, thank you for registering with ADX Group. To activate your security console and comply with our zero-trust baseline, please verify your email address.
              </p>

              <div style="background: #f1f5f9; border-radius: 8px; border: 1px solid #cbd5e1; padding: 18px; text-align: center; margin-bottom: 24px;">
                <span style="display: block; font-size: 11px; text-transform: uppercase; font-weight: 700; color: #64748b; letter-spacing: 0.8px; margin-bottom: 6px;">Your 6-Digit Security Code</span>
                <span style="font-family: monospace; font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #2563eb;">{code}</span>
              </div>

              <div style="text-align: center; margin-bottom: 28px;">
                <a href="{verify_url}" style="background: #2563eb; color: #ffffff; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-size: 14px; font-weight: 700; display: inline-block;">
                  Verify Email &amp; Launch Console &rarr;
                </a>
              </div>

              <p style="margin: 0; font-size: 12px; color: #64748b; line-height: 1.5; border-top: 1px solid #e2e8f0; padding-top: 16px;">
                Direct verification link: <a href="{verify_url}" style="color: #2563eb; word-break: break-all;">{verify_url}</a>
              </p>
            </td>
          </tr>
          <tr>
            <td style="background: #f8fafc; padding: 20px 32px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; line-height: 1.5;">
              <strong style="color: #0f172a;">ADX Group Cyber Systems</strong> &bull; Lead Cyber Systems Architect: Abdulrazaq Adeyemi<br>
              Direct Security Desk: <a href="mailto:contact@adxgroup.tech" style="color: #2563eb; text-decoration: none;">contact@adxgroup.tech</a> &bull; <a href="https://adxgroup.tech" style="color: #2563eb; text-decoration: none;">adxgroup.tech</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    sent = _send_smtp_email(clean_email, subject, html_body, text_body)

    record = {
        "id": f"ADX-VERIFY-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "type": "ACCOUNT_VERIFICATION",
        "to": clean_email,
        "name": clean_name,
        "code": code,
        "token": token,
        "verify_url": verify_url,
        "smtp_dispatched": sent,
        "status": "SENT_VIA_SMTP" if sent else "QUEUED_OUTBOX (SMTP_PASSWORD pending in Vercel)",
    }
    _record_to_outbox(record)

    return record


def send_login_alert(email: str, name: str, ip: str, user_agent: str = "") -> Dict[str, Any]:
    """Send security alert for new sign-in to account."""
    clean_email = email.strip().lower()
    clean_name = name.strip() or clean_email.split("@")[0].title()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = f"Security Notice: Successful Sign-in to ADX Console ({clean_email})"

    text_body = f"""Hello {clean_name},

A new sign-in was recorded for your ADX Group account:

Email: {clean_email}
Time: {now_str}
Client IP: {ip or 'Confidential'}

If this was you, no action is required. If you did not authorize this login, please sign in to your dashboard and change your password immediately.

ADX Group Cyber Security Desk
contact@adxgroup.tech
"""

    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family: sans-serif; padding: 20px; background: #f8fafc; color: #0f172a;">
  <div style="max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 24px;">
    <h2 style="color: #0f172a; margin-top: 0;">ADX Group Security Alert</h2>
    <p style="font-size: 14px; color: #334155;">Hello {clean_name}, a new sign-in to your ADX Console was verified.</p>
    <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin: 16px 0;">
      <tr><td style="padding: 6px 0; color: #64748b;">Account:</td><td style="font-weight: 700;">{clean_email}</td></tr>
      <tr><td style="padding: 6px 0; color: #64748b;">Timestamp:</td><td style="font-weight: 700;">{now_str}</td></tr>
      <tr><td style="padding: 6px 0; color: #64748b;">Client IP:</td><td style="font-family: monospace; font-weight: 700; color: #2563eb;">{ip or 'Edge Proxy'}</td></tr>
    </table>
    <p style="font-size: 12px; color: #64748b;">If this was not you, please contact security@adxgroup.tech immediately.</p>
  </div>
</body>
</html>"""

    sent = _send_smtp_email(clean_email, subject, html_body, text_body)

    record = {
        "id": f"ADX-ALERT-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "timestamp": now_str,
        "type": "LOGIN_SECURITY_ALERT",
        "to": clean_email,
        "ip": ip,
        "smtp_dispatched": sent,
        "status": "SENT_VIA_SMTP" if sent else "LOGGED_LOCAL",
    }
    _record_to_outbox(record)
    return record
