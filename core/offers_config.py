"""
Re-export configuration from core.public_config for backward compatibility.
All primary configuration now resides in core.public_config with EMPTY defaults.
"""

from core.public_config import (
    SPLASH_ENABLED,
    WHATSAPP_NUMBER,
    WHATSAPP_PREFILLED_MESSAGE,
    BOOKING_URL,
    LINKEDIN_URL,
    TWITTER_URL,
    NDPC_OFFICIAL_URL,
    DPCO_PARTNER_NAME,
    CAC_NAME_AND_RC,
    DEFAULT_CURRENCY,
    PRICING_CONFIG,
    TIMELINE_CONFIG,
    CASE_STUDIES,
    get_whatsapp_url,
    get_booking_url,
    get_linkedin_url,
    get_twitter_url,
    get_dpco_partner_name,
    get_cac_info,
    get_offer_price,
    get_offer_timeline,
    get_partners_list,
)

PARTNERS_LIST = get_partners_list()
