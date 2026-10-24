"""
ADX Group — Client Lead & Audit Notification Dispatcher (Gate 4).
Validates and records incoming client project requests and scan leads.
"""

import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List

DATA_DIR = (
    Path("/tmp/adxgroup_data")
    if os.getenv("VERCEL")
    else Path(__file__).resolve().parent.parent / "data"
)
LEADS_FILE = DATA_DIR / "leads.json"


def _ensure_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not LEADS_FILE.exists():
        LEADS_FILE.write_text("[]", encoding="utf-8")


def get_all_leads() -> List[Dict[str, Any]]:
    """Return all recorded client project and audit leads for the Owner Admin Console."""
    _ensure_storage()
    try:
        return json.loads(LEADS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def record_client_lead(
    company_or_name: str,
    email: str,
    division: str,
    message: str,
    domain: str = "",
) -> Dict[str, Any]:
    """Gate 4: Validate client lead submission and persist to ADX Group lead ledger."""
    clean_email = (email or "").strip()
    clean_name = (company_or_name or "").strip()
    clean_msg = (message or "").strip()

    if not clean_email or "@" not in clean_email or "." not in clean_email:
        return {
            "gate_4_passed": False,
            "error": "GATE-04 FALSE: Please provide a valid business or contact email address.",
        }
    if not clean_name:
        return {
            "gate_4_passed": False,
            "error": "GATE-04 FALSE: Please provide your name or company name.",
        }

    existing = get_all_leads()

    entry = {
        "id": f"ADX-LEAD-{len(existing) + 101}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "company_or_name": clean_name,
        "email": clean_email,
        "division": division or "General Inquiry",
        "domain": domain.strip(),
        "message": clean_msg,
        "routed_to": "contact@adxgroup.tech",
    }
    existing.insert(0, entry)
    LEADS_FILE.write_text(json.dumps(existing[:500], indent=2), encoding="utf-8")

    return {
        "gate_4_passed": True,
        "lead": entry,
        "confirmation": (
            f"Inquiry {entry['id']} logged and routed to contact@adxgroup.tech. "
            f"An ADX Systems engineer will respond within 12 hours."
        ),
    }
