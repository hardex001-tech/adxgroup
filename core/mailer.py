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
    """Send live email via SMTP (Zoho, Gmail, or custom) if credentials exist."""
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port_str = os.getenv("SMTP_PORT", "").strip()
    smtp_user = os.getenv("SMTP_USER", "").strip() or "contact@adxgroup.tech"
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_from = os.getenv("SMTP_FROM", "").strip()

    if not smtp_host:
        if "@gmail.com" in smtp_user.lower():
            smtp_host = "smtp.gmail.com"
        else:
            smtp_host = "smtp.zoho.com"

    if not smtp_port_str:
        smtp_port = 465 if ("gmail" in smtp_host or "zoho" in smtp_host) else 587
    else:
        try:
            smtp_port = int(smtp_port_str)
        except ValueError:
            smtp_port = 465

    if not smtp_from:
        smtp_from = f"ADX Group Security <{smtp_user}>"

    if not smtp_password:
        print(f"[ADX MAILER] Notice: SMTP_PASSWORD is not configured in environment. Alert recorded to local outbox. To deliver live to inbox, add SMTP_PASSWORD to Vercel Environment Variables.")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = to_email
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=12) as server:
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=12) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, [to_email], msg.as_string())
        print(f"[ADX MAILER] Live email dispatched successfully to {to_email} via {smtp_host}:{smtp_port}")
        return True
    except Exception as exc:
        print(f"[ADX MAILER] SMTP dispatch failed to {to_email} via {smtp_host}:{smtp_port}: {exc}")
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


def send_login_alert(email: str, name: str, ip: str, user_agent: str = "", is_proxy_or_vpn: bool = False) -> Dict[str, Any]:
    """Send zero-trust security alert for new sign-in to account, checking for proxy/VPN and anomalous origin."""
    clean_email = email.strip().lower()
    clean_name = name.strip() or clean_email.split("@")[0].title()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    route_status = "⚠️ Proxy / VPN / Multi-Hop Hop Detected" if is_proxy_or_vpn else "Direct Sovereign Edge Handshake"
    subject = f"Security Notice: New Login Verified for {clean_email} [{ip or 'Edge'}]"

    text_body = f"""Hello {clean_name},

A new sign-in session was established for your ADX Group Client Console:

Account Email:   {clean_email}
Session Time:    {now_str}
Client IP:       {ip or 'Edge Proxy'}
Route Telemetry: {route_status}
Device System:   {user_agent or 'Standard Web Browser'}

If you initiated this sign-in, you may safely disregard this message.

EMERGENCY SECURITY PROTOCOL:
If you did not initiate this sign-in, an unauthorized party may have obtained your credentials. Reset your password immediately and secure your workspace:
https://adxgroup.tech/login?reset=immediate

ADX Group Sovereign Cyber Security Desk
security@adxgroup.tech • Abuja, Nigeria
"""

    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 24px; background: #0b1120; color: #f8fafc;">
  <div style="max-width: 560px; margin: 0 auto; background: #111827; border-radius: 12px; border: 1px solid rgba(56, 189, 248, 0.3); padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px;">
      <span style="display: inline-block; width: 12px; height: 12px; border-radius: 50%; background: {'#f59e0b' if is_proxy_or_vpn else '#10b981'}; box-shadow: 0 0 10px {'#f59e0b' if is_proxy_or_vpn else '#10b981'};"></span>
      <h2 style="color: #ffffff; margin: 0; font-size: 1.25rem; font-weight: 800; letter-spacing: -0.02em;">ADX Zero-Trust Security Alert</h2>
    </div>
    
    <p style="font-size: 14px; color: #cbd5e1; line-height: 1.6; margin-bottom: 20px;">
      Hello <strong style="color: #ffffff;">{clean_name}</strong>, a new authentication event was verified for your ADX Console.
    </p>

    <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin: 20px 0; background: rgba(15, 23, 42, 0.6); border-radius: 8px; border: 1px solid rgba(255,255,255,0.08);">
      <tr>
        <td style="padding: 10px 14px; color: #94a3b8; border-bottom: 1px solid rgba(255,255,255,0.06);">Account:</td>
        <td style="padding: 10px 14px; font-weight: 700; color: #ffffff; border-bottom: 1px solid rgba(255,255,255,0.06);">{clean_email}</td>
      </tr>
      <tr>
        <td style="padding: 10px 14px; color: #94a3b8; border-bottom: 1px solid rgba(255,255,255,0.06);">Timestamp:</td>
        <td style="padding: 10px 14px; font-weight: 700; color: #ffffff; border-bottom: 1px solid rgba(255,255,255,0.06);">{now_str}</td>
      </tr>
      <tr>
        <td style="padding: 10px 14px; color: #94a3b8; border-bottom: 1px solid rgba(255,255,255,0.06);">Client IP:</td>
        <td style="padding: 10px 14px; font-family: monospace; font-weight: 700; color: #38bdf8; border-bottom: 1px solid rgba(255,255,255,0.06);">{ip or 'Edge Proxy'}</td>
      </tr>
      <tr>
        <td style="padding: 10px 14px; color: #94a3b8; border-bottom: 1px solid rgba(255,255,255,0.06);">Route Integrity:</td>
        <td style="padding: 10px 14px; font-weight: 700; color: {'#f59e0b' if is_proxy_or_vpn else '#34d399'}; border-bottom: 1px solid rgba(255,255,255,0.06);">{route_status}</td>
      </tr>
      <tr>
        <td style="padding: 10px 14px; color: #94a3b8;">Client System:</td>
        <td style="padding: 10px 14px; color: #cbd5e1; font-size: 12px; font-family: monospace;">{user_agent[:60] if user_agent else 'Standard Web Browser'}</td>
      </tr>
    </table>

    <div style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; border-radius: 6px; padding: 14px; margin: 24px 0;">
      <div style="font-weight: 700; color: #fca5a5; font-size: 13px; margin-bottom: 4px;">Did not authorize this sign-in?</div>
      <p style="font-size: 12px; color: #fecaca; margin: 0; line-height: 1.5;">
        If this was not you, someone may have compromised your password. Secure your account immediately:
      </p>
      <div style="margin-top: 10px;">
        <a href="https://adxgroup.tech/login?reset=immediate" style="display: inline-block; background: #dc2626; color: #ffffff; text-decoration: none; font-size: 12px; font-weight: 700; padding: 8px 16px; border-radius: 6px;">
          Lock Down Account &amp; Reset Password &rarr;
        </a>
      </div>
    </div>

    <div style="font-size: 11px; color: #64748b; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 16px;">
      ADX Group Cyber Security Incident Desk &bull; Abuja, Nigeria &bull; Silent Innovation. Absolute Defense.
    </div>
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
        "is_proxy_or_vpn": is_proxy_or_vpn,
        "user_agent": user_agent,
        "smtp_dispatched": sent,
        "status": "SENT_VIA_SMTP" if sent else "LOGGED_LOCAL",
    }
    _record_to_outbox(record)
    return record


def send_password_reset_email(email: str, name: str, token: str, code: str) -> Dict[str, Any]:
    """Send cryptographic password reset email with 6-digit OTP code and direct reset link."""
    clean_email = email.strip().lower()
    clean_name = name.strip() or clean_email.split("@")[0].title()
    reset_url = f"{APP_BASE_URL}/login?reset_token={token}"
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = f"ADX Group Security: Password Reset Request ({code})"

    text_body = f"""Hello {clean_name},

A password reset was requested for your ADX Group Console account ({clean_email}).

Your 6-Digit Verification Code is: {code}

Alternatively, reset your password directly by visiting:
{reset_url}

This password reset link expires in 60 minutes.

If you did not request this reset, your account is secure and you may safely disregard this message.

ADX Group Cyber Security Desk
contact@adxgroup.tech | https://adxgroup.tech
"""

    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 24px; background: #f8fafc; color: #0f172a;">
  <div style="max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 14px rgba(15,23,42,0.06);">
    <div style="background: #0f172a; padding: 22px 28px; border-bottom: 2px solid #2563eb;">
      <span style="color: #ffffff; font-size: 17px; font-weight: 800; letter-spacing: -0.3px;">ADX GROUP</span>
      <span style="display: block; color: #94a3b8; font-size: 11px; text-transform: uppercase; margin-top: 2px;">Zero-Trust Password Recovery Gateway</span>
    </div>
    <div style="padding: 28px;">
      <h2 style="color: #0f172a; margin-top: 0; font-size: 19px;">Reset Your Console Password</h2>
      <p style="font-size: 14px; color: #475569; line-height: 1.55;">
        Hello <strong>{clean_name}</strong>, a request was received to reset your password. Use the verification code below or click the direct button to set a new password.
      </p>
      <div style="background: #f1f5f9; border-radius: 8px; border: 1px solid #cbd5e1; padding: 18px; text-align: center; margin: 20px 0;">
        <span style="display: block; font-size: 11px; text-transform: uppercase; font-weight: 700; color: #64748b; margin-bottom: 6px;">Your 6-Digit Password Reset Code</span>
        <span style="font-family: monospace; font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #2563eb;">{code}</span>
      </div>
      <div style="text-align: center; margin: 24px 0;">
        <a href="{reset_url}" style="background: #0f172a; color: #ffffff; text-decoration: none; padding: 12px 26px; border-radius: 6px; font-size: 14px; font-weight: 700; display: inline-block;">
          Set New Password &rarr;
        </a>
      </div>
      <p style="font-size: 12px; color: #64748b; line-height: 1.5; border-top: 1px solid #e2e8f0; padding-top: 14px; margin: 0;">
        This token expires in 60 minutes. If you did not initiate this request, no action is needed.
      </p>
    </div>
  </div>
</body>
</html>"""

    sent = _send_smtp_email(clean_email, subject, html_body, text_body)

    record = {
        "id": f"ADX-RESET-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "timestamp": now_str,
        "type": "PASSWORD_RESET",
        "to": clean_email,
        "code": code,
        "token": token,
        "smtp_dispatched": sent,
        "status": "SENT_VIA_SMTP" if sent else "QUEUED_OUTBOX",
    }
    _record_to_outbox(record)
    return record


def send_2fa_challenge_email(email: str, name: str, code: str, ip: str, is_proxy_or_vpn: bool = False) -> Dict[str, Any]:
    """Dispatch instantaneous 6-digit confirmation code for anomalous IP / new device login."""
    clean_email = email.strip().lower()
    clean_name = name.strip() or clean_email.split("@")[0].title()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = f"Your ADX 2FA Code: {code} (New Device / IP Sign-In)"

    text_body = f"""Hello {clean_name},

A sign-in attempt was detected from a new device or IP address:
Account:     {clean_email}
Origin IP:   {ip or 'Unspecified'}
Time:        {now_str}

YOUR 6-DIGIT VERIFICATION CODE:
================================
         {code}
================================

Enter this code in your browser to authorize this device and access your ADX Console. This code expires in 15 minutes.

If this was not you, someone knows your password. Lock down your account immediately at https://adxgroup.tech/login?reset=immediate

ADX Group Zero-Trust Security Incident Desk
security@adxgroup.tech
"""

    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 24px; background: #0b1120; color: #f8fafc;">
  <div style="max-width: 540px; margin: 0 auto; background: #111827; border-radius: 14px; border: 1px solid rgba(56, 189, 248, 0.35); padding: 36px; box-shadow: 0 12px 35px rgba(0,0,0,0.6);">
    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px;">
      <span style="display: inline-block; width: 12px; height: 12px; border-radius: 50%; background: #38bdf8; box-shadow: 0 0 10px #38bdf8;"></span>
      <h2 style="color: #ffffff; margin: 0; font-size: 1.3rem; font-weight: 800;">ADX Multi-Factor Authentication</h2>
    </div>
    
    <p style="font-size: 14px; color: #cbd5e1; line-height: 1.6; margin-bottom: 18px;">
      Hello <strong style="color: #ffffff;">{clean_name}</strong>, a sign-in was initiated from a <strong style="color: #38bdf8;">new device or IP address</strong> ({ip or 'Edge Proxy'}).
    </p>

    <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 12px; padding: 22px; text-align: center; margin: 24px 0;">
      <div style="font-size: 11px; font-family: monospace; color: #94a3b8; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 8px;">6-DIGIT VERIFICATION CODE</div>
      <div style="font-size: 36px; font-family: monospace; font-weight: 800; letter-spacing: 8px; color: #38bdf8; text-shadow: 0 0 20px rgba(56, 189, 248, 0.5);">{code}</div>
      <div style="font-size: 12px; color: #64748b; margin-top: 8px;">Valid for 15 minutes &bull; Do not share this code</div>
    </div>

    <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin: 20px 0; background: rgba(15, 23, 42, 0.5); border-radius: 8px; border: 1px solid rgba(255,255,255,0.08);">
      <tr><td style="padding: 8px 12px; color: #94a3b8;">Account:</td><td style="padding: 8px 12px; font-weight: 700; color: #ffffff;">{clean_email}</td></tr>
      <tr><td style="padding: 8px 12px; color: #94a3b8;">Attempt IP:</td><td style="padding: 8px 12px; font-family: monospace; font-weight: 700; color: #38bdf8;">{ip or 'Confidential'}</td></tr>
      <tr><td style="padding: 8px 12px; color: #94a3b8;">Timestamp:</td><td style="padding: 8px 12px; color: #ffffff;">{now_str}</td></tr>
    </table>

    <div style="font-size: 11px; color: #64748b; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 16px;">
      If you did not initiate this request, someone may be trying to access your account. Change your password immediately.<br>
      ADX Group Cyber Security Incident Desk &bull; Silent Innovation. Absolute Defense.
    </div>
  </div>
</body>
</html>"""

    sent = _send_smtp_email(clean_email, subject, html_body, text_body)

    record = {
        "id": f"ADX-2FA-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "timestamp": now_str,
        "type": "LOGIN_2FA_CHALLENGE",
        "to": clean_email,
        "code": code,
        "ip": ip,
        "smtp_dispatched": sent,
        "status": "SENT_VIA_SMTP" if sent else "LOGGED_LOCAL",
    }
    _record_to_outbox(record)
    return record
