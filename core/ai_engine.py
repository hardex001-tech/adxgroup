"""
ADX Group — Artificial Intelligence Analysis & 24/7 Client Consultation Engine.
Includes:
1. Gate 3 Input Safety Verification (Prompt Injection Defense)
2. Automated Root-Cause Executive Security Analysis
3. 24/7 Autonomous Client Consultant for ADX Cyber, Cloud, and AI Services
"""

import os
import re
from typing import Any, Dict, List

import httpx

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"system\s+prompt",
    r"reveal\s+your\s+(secret|api\s+key|instructions)",
    r"drop\s+table",
    r"<script",
]


def verify_prompt_safety(user_message: str) -> Dict[str, Any]:
    """Gate 3: Check incoming message for prompt injection or script payload attempts."""
    text = (user_message or "").strip()
    if not text:
        return {"safe": False, "reason": "Empty message payload."}
    if len(text) > 1500:
        return {"safe": False, "reason": "Input exceeds maximum safe token length (1500 chars)."}

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return {
                "safe": False,
                "reason": "GATE-03 FALSE: Prompt injection or unsafe instruction pattern blocked by ADX AI Guard.",
            }
    return {"safe": True, "reason": "GATE-03 TRUE: Input verified safe."}


def generate_ai_executive_summary(scan_result: Dict[str, Any]) -> str:
    """Synthesize the 5-vector diagnostic results into a plain-English AI Executive Brief."""
    domain = scan_result["domain"]
    score = scan_result["score"]
    grade = scan_result["grade"]
    failed = [g for g in scan_result["gates"] if not g["state"]]

    if not failed:
        return (
            f"ADX AI Assessment for {domain} (Grade {grade}, Score {score}/100): "
            f"All 5 external diagnostic gates returned TRUE. SSL/TLS encryption, anti-spoofing DNS records (SPF/DMARC), "
            f"HTTP defensive headers, and asset exposure controls meet enterprise baseline standards. "
            f"Recommended Next Step: Deploy automated uptime and drift monitoring or integrate internal AI document search (RAG)."
        )

    failed_names = ", ".join(g["vector"] for g in failed)
    critical_notes = []
    for g in failed:
        if g["gate_id"] == "GATE-02":
            critical_notes.append(
                "Email spoofing protection is incomplete, allowing external actors to send phishing emails impersonating this domain."
            )
        elif g["gate_id"] == "GATE-03":
            critical_notes.append(
                "Missing HTTP defensive headers leave browser sessions exposed to clickjacking and frame injection."
            )
        elif g["gate_id"] == "GATE-01":
            critical_notes.append(
                "TLS cryptographic configuration requires immediate certificate or protocol hardening."
            )
        elif g["gate_id"] == "GATE-05":
            critical_notes.append(
                "Server technology banners or sensitive configuration paths are publicly visible to automated scanners."
            )

    impact_str = " ".join(critical_notes[:2])
    return (
        f"ADX AI Root-Cause Brief for {domain} (Grade {grade}, Score {score}/100): "
        f"{len(failed)} of 5 diagnostic gates returned FALSE ({failed_names}). "
        f"Business Impact: {impact_str} "
        f"ADX Group can remediate all identified gaps and lock down the perimeter within 24 to 48 hours."
    )


async def ask_adx_ai_consultant(user_message: str) -> Dict[str, Any]:
    """Process client questions via the ADX AI Consultant with safety verification."""
    safety = verify_prompt_safety(user_message)
    if not safety["safe"]:
        return {
            "gate_3_passed": False,
            "reply": safety["reason"],
            "engine": "ADX-AI-Guard",
        }

    # Optional live LLM API call if GITHUB_TOKEN or OPENAI_API_KEY is configured
    api_key = os.getenv("GITHUB_TOKEN") or os.getenv("OPENAI_API_KEY")
    if api_key:
        try:
            endpoint = (
                "https://models.inference.ai.azure.com/chat/completions"
                if os.getenv("GITHUB_TOKEN")
                else "https://api.openai.com/v1/chat/completions"
            )
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(
                    endpoint,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [
                            {
                                "role": "system",
                                "content": (
                                    "You are the official AI Systems Consultant for ADX Group (adxgroup.tech). "
                                    "ADX Group has 3 divisions: "
                                    "1. ADX Cyber (Website & API security audits, DNS/DMARC anti-spoofing, WAF setup, $350-$1,200 fixed-scope or $350/mo retainer). "
                                    "2. ADX Cloud & Systems (Python/FastAPI microservices, Docker, Azure/AWS deployment, automated backups). "
                                    "3. ADX Intelligence (Private enterprise AI assistants, RAG document search, workflow automation). "
                                    "Keep answers concise, executive, helpful, and direct clients to contact@adxgroup.tech."
                                ),
                            },
                            {"role": "user", "content": user_message},
                        ],
                        "max_tokens": 250,
                        "temperature": 0.3,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"].strip()
                    return {
                        "gate_3_passed": True,
                        "reply": content,
                        "engine": "ADX-Neural-Core",
                    }
        except Exception:
            pass

    # Built-in High-Reliability Expert Knowledge Base Fallback
    q = user_message.lower()
    if any(k in q for k in ("price", "cost", "how much", "pricing", "rate", "quote")):
        reply = (
            "ADX Group operates on transparent, fixed-scope B2B pricing:\n"
            "• External Security & Infrastructure Audit: $350 – $950 (delivered in 48 hours with full remediation guide)\n"
            "• Cloud Sentinel Retainer (24/7 Monitoring, Backups & Patching): $350/month\n"
            "• Custom AI Document Assistant (RAG) or FastAPI Cloud Deployment: $600 – $2,000 fixed scope.\n"
            "You can request an official invoice or scope brief via contact@adxgroup.tech."
        )
    elif any(k in q for k in ("ai", "rag", "chatbot", "automation", "agent", "llm")):
        reply = (
            "Our ADX Intelligence division builds private AI systems tailored for businesses:\n"
            "1. Private Document AI (RAG): Search internal PDFs, contracts, and SOPs securely without leaking data.\n"
            "2. Autonomous Workflow Agents: Automate customer triage, lead qualification, and report generation.\n"
            "3. AI Security Guardrails: Protect corporate AI endpoints from prompt injection and data leaks."
        )
    elif any(k in q for k in ("security", "hack", "audit", "vulnerability", "dmarc", "ssl", "waf", "protect")):
        reply = (
            "ADX Cyber secures client websites and cloud infrastructure across 4 layers:\n"
            "1. Edge WAF & DDoS Filtering (blocking SQLi, XSS, and malicious bots before reaching your server).\n"
            "2. Email Anti-Spoofing (enforcing strict SPF, DKIM, and DMARC so attackers cannot impersonate your domain).\n"
            "3. Server & Database Isolation with automated weekly vulnerability scanning.\n"
            "4. Daily encrypted off-site backups for instant recovery. Try our live scanner above on your domain!"
        )
    elif any(k in q for k in ("partner", "agency", "white label", "whitelabel", "subcontract")):
        reply = (
            "Yes—ADX Group partners with web development and marketing agencies worldwide on a confidential white-label basis. "
            "You handle the client relationship while our engineering team handles backend cloud deployment, security hardening, "
            "and AI integration behind the scenes. Reach out to contact@adxgroup.tech to set up a partner channel."
        )
    else:
        reply = (
            "Welcome to ADX Group (adxgroup.tech). We engineer solutions across three core divisions:\n"
            "• ADX Cyber: Website & API Security Audits, Anti-Spoofing (DMARC/SPF), and Cloud Firewall Hardening.\n"
            "• ADX Cloud & Systems: Python/FastAPI Backend Architecture, Docker, and Azure/AWS Automation.\n"
            "• ADX Intelligence: Private Business AI Assistants & Workflow Automation.\n"
            "Run a free live diagnostic on your domain above, or ask me about pricing, AI automation, or security audits!"
        )

    return {
        "gate_3_passed": True,
        "reply": reply,
        "engine": "ADX-Expert-Core",
    }
