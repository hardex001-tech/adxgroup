"""
Central business configuration for ADX Group solution offers, pricing, and integrations.
All customizable business values, contact endpoints, and partner disclosures live here.
"""

# Brand & UI Configuration
SPLASH_ENABLED = False  # Set to True to enable <=800ms brand splash once per session

# Contact & Booking Endpoints
WHATSAPP_NUMBER = "[PLACEHOLDER: WhatsApp number in international format - e.g. +234XXXXXXXXXX]"
WHATSAPP_PREFILLED_MESSAGE = (
    "Hello ADX Group, I would like to inquire about your cybersecurity and NDPA compliance services for my organization."
)
BOOKING_URL = "[PLACEHOLDER: 20-minute booking link - e.g. https://calendly.com/adxgroup/security-review]"

# Official Regulatory & Partner Data
NDPC_OFFICIAL_URL = "[PLACEHOLDER: verified NDPC URL - e.g. https://ndpc.gov.ng]"
PARTNER_DPCO_NAME = "[PLACEHOLDER: partner DPCO name]"

# Currency Pricing Configuration (Single place to update starting prices)
DEFAULT_CURRENCY = "NGN"

PRICING_CONFIG = {
    "shield": {
        "NGN": "[PLACEHOLDER: Shield Starting Price NGN - e.g. ₦750,000]",
        "USD": "[PLACEHOLDER: Shield Starting Price USD - e.g. $1,200]",
    },
    "comply": {
        "NGN": "[PLACEHOLDER: Comply Starting Price NGN - e.g. ₦1,200,000]",
        "USD": "[PLACEHOLDER: Comply Starting Price USD - e.g. $1,800]",
    },
    "resilience": {
        "NGN": "[PLACEHOLDER: Resilience Starting Price NGN - e.g. ₦950,000]",
        "USD": "[PLACEHOLDER: Resilience Starting Price USD - e.g. $1,500]",
    },
    "ai-automation": {
        "NGN": "[PLACEHOLDER: AI & Automation Starting Price NGN - e.g. ₦850,000]",
        "USD": "[PLACEHOLDER: AI & Automation Starting Price USD - e.g. $1,400]",
    },
}

# Engagement Timeline Placeholders
TIMELINE_CONFIG = {
    "shield": "[PLACEHOLDER: Shield Engagement Timeline - e.g. 2 to 3 weeks]",
    "comply": "[PLACEHOLDER: Comply Engagement Timeline - e.g. 4 to 6 weeks]",
    "resilience": "[PLACEHOLDER: Resilience Engagement Timeline - e.g. 3 to 4 weeks]",
    "ai-automation": "[PLACEHOLDER: AI Automation Engagement Timeline - e.g. 3 to 5 weeks]",
}

# Verified Partners & Infrastructure (Renders only honest, verified entries)
PARTNERS_LIST = [
    {
        "name": "Data Protection Compliance Partner",
        "category": "Licensed DPCO",
        "description": f"Mandatory annual NDPA Compliance Audit Returns are filed exclusively in partnership with {PARTNER_DPCO_NAME}.",
        "is_dpco": True,
    },
    {
        "name": "Cloudflare",
        "category": "Edge & DNS Security",
        "description": "DNSSEC, authenticated SPF/DMARC routing, and perimeter WAF infrastructure.",
        "is_dpco": False,
    },
    {
        "name": "Vercel Global Edge",
        "category": "Serverless Infrastructure",
        "description": "Stateless serverless compute nodes with isolated execution boundaries.",
        "is_dpco": False,
    },
    {
        "name": "Zoho Enterprise Mail",
        "category": "Email Security & TLS",
        "description": "Hardened MX and authenticated SPF/DKIM mail routing.",
        "is_dpco": False,
    },
]

# Case Studies List: Empty by default. The component renders ONLY when entries exist.
CASE_STUDIES = []
