"""
ADX Group — Public Business Configuration & Placeholder Guard.
Single source of truth for all external endpoints, partner disclosures, and pricing.
All customizable values default to EMPTY strings ("").
When values are empty, UI elements are conditionally hidden or use safe defaults.
No text containing "[PLACEHOLDER" or "PLACEHOLDER:" may ever render publicly.
"""

import os
import re
import urllib.parse
from typing import Dict, List, Optional

# UI & Brand flags
SPLASH_ENABLED: bool = False

# External Endpoints & Social Links (Empty defaults)
WHATSAPP_NUMBER: str = os.getenv("WHATSAPP_NUMBER", "").strip()
WHATSAPP_PREFILLED_MESSAGE: str = (
    "Hello ADX Group, I would like to inquire about your cybersecurity and NDPA compliance services for my organization."
)
BOOKING_URL: str = os.getenv("BOOKING_URL", "").strip()
LINKEDIN_URL: str = os.getenv("LINKEDIN_URL", "").strip()
TWITTER_URL: str = os.getenv("TWITTER_URL", "").strip()

# Statutory Disclosures & Compliance Partners
NDPC_OFFICIAL_URL: str = "https://ndpc.gov.ng"
DPCO_PARTNER_NAME: str = os.getenv("DPCO_PARTNER_NAME", "").strip()
CAC_NAME_AND_RC: str = os.getenv("CAC_NAME_AND_RC", "").strip()

# Solution Pricing (Empty defaults -> UI displays 'Contact us for pricing')
DEFAULT_CURRENCY: str = "NGN"

PRICING_CONFIG: Dict[str, Dict[str, str]] = {
    "shield": {
        "NGN": os.getenv("PRICE_SHIELD_NGN", "").strip(),
        "USD": os.getenv("PRICE_SHIELD_USD", "").strip(),
    },
    "comply": {
        "NGN": os.getenv("PRICE_COMPLY_NGN", "").strip(),
        "USD": os.getenv("PRICE_COMPLY_USD", "").strip(),
    },
    "resilience": {
        "NGN": os.getenv("PRICE_RESILIENCE_NGN", "").strip(),
        "USD": os.getenv("PRICE_RESILIENCE_USD", "").strip(),
    },
    "ai-automation": {
        "NGN": os.getenv("PRICE_AI_NGN", "").strip(),
        "USD": os.getenv("PRICE_AI_USD", "").strip(),
    },
}

# Engagement Timelines (Empty defaults -> omitted in UI)
TIMELINE_CONFIG: Dict[str, str] = {
    "shield": os.getenv("TIMELINE_SHIELD", "").strip(),
    "comply": os.getenv("TIMELINE_COMPLY", "").strip(),
    "resilience": os.getenv("TIMELINE_RESILIENCE", "").strip(),
    "ai-automation": os.getenv("TIMELINE_AI", "").strip(),
}


def get_whatsapp_url() -> str:
    """
    Build WhatsApp link only from a valid number (digits, international format).
    Returns empty string if WHATSAPP_NUMBER is empty or invalid.
    """
    raw = WHATSAPP_NUMBER.strip()
    if not raw or "PLACEHOLDER" in raw.upper():
        return ""
    # Extract only digits and leading plus
    digits = re.sub(r"[^\d]", "", raw)
    if len(digits) < 10:
        return ""
    encoded_text = urllib.parse.quote(WHATSAPP_PREFILLED_MESSAGE)
    return f"https://wa.me/{digits}?text={encoded_text}"


def get_booking_url() -> str:
    """Return booking URL if valid and non-placeholder; otherwise empty string."""
    raw = BOOKING_URL.strip()
    if not raw or "PLACEHOLDER" in raw.upper():
        return ""
    return raw


def get_linkedin_url() -> str:
    raw = LINKEDIN_URL.strip()
    if not raw or "PLACEHOLDER" in raw.upper():
        return ""
    return raw


def get_twitter_url() -> str:
    raw = TWITTER_URL.strip()
    if not raw or "PLACEHOLDER" in raw.upper():
        return ""
    return raw


def get_dpco_partner_name() -> str:
    raw = DPCO_PARTNER_NAME.strip()
    if not raw or "PLACEHOLDER" in raw.upper():
        return ""
    return raw


def get_cac_info() -> str:
    raw = CAC_NAME_AND_RC.strip()
    if not raw or "PLACEHOLDER" in raw.upper():
        return ""
    return raw


def get_offer_price(slug: str, currency: str = "NGN") -> str:
    prices = PRICING_CONFIG.get(slug, {})
    val = prices.get(currency.upper(), "").strip()
    if not val or "PLACEHOLDER" in val.upper():
        return "Contact us for pricing"
    return val


def get_offer_timeline(slug: str) -> str:
    val = TIMELINE_CONFIG.get(slug, "").strip()
    if not val or "PLACEHOLDER" in val.upper():
        return ""
    return val


def get_partners_list() -> List[Dict[str, str]]:
    """Returns list of honest, verified infrastructure and partner disclosures."""
    dpco = get_dpco_partner_name()
    partners = []
    if dpco:
        partners.append({
            "name": dpco,
            "category": "Licensed DPCO Partner",
            "description": f"Annual statutory NDPA Compliance Audit Returns (CAR) filed in coordination with {dpco}.",
            "is_dpco": True,
        })

    # Verified by live DNS (alex/elsa.ns.cloudflare.com, mx.zoho.com, Vercel 76.76.21.21)
    partners.extend([
        {
            "name": "Cloudflare",
            "category": "DNS & DDoS Protection",
            "description": "DNS management, DNSSEC verification, and perimeter proxy security.",
            "is_dpco": False,
        },
        {
            "name": "Vercel",
            "category": "Production Cloud Hosting",
            "description": "FastAPI ASGI deployment on Vercel's global Anycast infrastructure.",
            "is_dpco": False,
        },
        {
            "name": "Zoho Mail",
            "category": "Corporate Mail Routing",
            "description": "Hardened MX and authenticated SPF/DKIM business email delivery.",
            "is_dpco": False,
        },
    ])
    return partners


# Client Case Studies (empty by default until written attestation)
CASE_STUDIES: List[Dict[str, str]] = []

# Deliverable sample files
SAMPLE_REPORT_URL: str = "/static/reports/sample-audit-report.pdf"


def get_sample_report_url() -> str:
    return SAMPLE_REPORT_URL
