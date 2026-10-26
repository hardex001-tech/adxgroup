"""
Detailed content models and specifications for ADX Group's 4 core solution offers.
"""

from core.public_config import (
    get_dpco_partner_name,
    get_dpco_notice,
    get_shield_price_note,
    get_booking_url,
    get_offer_price,
    get_offer_timeline,
)

def _build_dpco_notice() -> str:
    return get_dpco_notice()


def _build_dpco_step_desc() -> str:
    dpco = get_dpco_partner_name()
    if dpco:
        return f"We assemble technical safeguards documentation and coordinate directly with {dpco} for statutory filing."
    return "We assemble technical safeguards documentation for your organization to submit through a licensed DPCO."

OFFERS_DICT = {
    "shield": {
        "slug": "shield",
        "name": "ADX Shield: Email Security Baseline Assessment",
        "tagline": "Email Spoofing Defense, DMARC Enforcement & Identity Baseline",
        "short_desc": "A focused pilot assessment to uncover email impersonation risks, verify SPF, DKIM, and DMARC enforcement, review essential account controls, and guide prioritized remediation for your domain.",
        "badge": "Pilot Offering &bull; Email Security Baseline",
        "icon": "shield",
        "target_audience": "Nigerian businesses, growing fintechs, legal practices, and corporate teams using Google Workspace, Microsoft 365, or Zoho Mail that want to defend executive communications against spoofing and Business Email Compromise (BEC).",
        "problem_statement": (
            "Email spoofing and executive impersonation remain the primary vector for Business Email Compromise (BEC) and wire-transfer fraud in Nigeria. "
            "When domain authentication is missing or left in passive monitoring mode (p=none), threat actors can forge messages that appear to come directly from your company. "
            "Publishing DNS records alone does not prove all outbound mail is authenticated or that all accounts are protected. "
            "Records must align with actual sending services, and essential administrative controls must be verified."
        ),
        "customer_prerequisites": [
            "List of corporate domains and authorized sending services (e.g. Google Workspace, Microsoft 365, Zoho Mail, marketing or transactional mail hosts).",
            "DNS administrative access or an assigned technical contact capable of publishing DNS records.",
            "Signed assessment scope and written authorization prior to technical review.",
        ],
        "deliverables": [
            "Assessment scope and written authorization agreement.",
            "SPF, DKIM, and DMARC record generation, alignment, and staged enforcement guidance (moving safely to quarantine/reject).",
            "Business email compromise (BEC) posture review across your primary mail provider (Google Workspace, Microsoft 365, or Zoho Mail).",
            "Selected account-security observations: Multi-Factor Authentication (MFA) enforcement review and cloud console access audit (where evidence is provided).",
            "Standardized employee offboarding checklist to revoke access tokens, device sessions, and API credentials.",
            "Prioritized Findings Register with clear risk rationale and tailored remediation guidance.",
            "Verification of agreed fixes with post-remediation testing and final assessment summary report with documented limitations.",
        ],
        "engagement_steps": [
            {
                "step": "01",
                "title": "Scope & Authorization",
                "desc": "We confirm in-scope domains and authorized sending services under a written authorization agreement.",
            },
            {
                "step": "02",
                "title": "Baseline Assessment & Findings",
                "desc": "We inspect DNS authentication records, analyze mail headers, review provided account-security evidence, and compile the prioritized findings register.",
            },
            {
                "step": "03",
                "title": "Remediation & Fix Verification",
                "desc": "We provide step-by-step configuration playbooks, verify agreed DNS and policy fixes upon publication, and deliver the final report.",
            },
        ],
        "not_included": [
            "Penetration testing, exploit execution, or adversary simulation.",
            "Guarantees of total immunity from phishing or cyberattacks.",
            "Statutory compliance certifications or legal regulatory opinions.",
            "Direct licensing or provisioning costs of third-party identity or email providers.",
            "Unapproved or unauthorized modifications to production systems.",
        ],
        "limitations_note": "DNS records alone do not prove all outbound mail is authenticated or that all accounts are protected. This is a pilot offering providing technical baseline evaluation; it is not a compliance certification or guarantee of immunity.",
        "timeline": get_offer_timeline("shield"),
        "pricing": {"NGN": get_offer_price("shield", "NGN"), "USD": get_offer_price("shield", "USD")},
        "price_note": get_shield_price_note(),
        "cta_label": "Request Assessment Scope",
        "cta_url": get_booking_url(),
        "meta_title": "ADX Shield | Email Security Baseline Assessment Nigeria",
        "meta_description": "Protect your domain against executive spoofing, BEC fraud, and credential compromise with the ADX Shield Email Security Baseline Assessment pilot.",
        "seo_keywords": "DMARC setup Nigeria, business email fraud protection Nigeria, BEC defense Lagos, SPF DKIM enforcement Abuja",
    },
    "comply": {
        "slug": "comply",
        "name": "ADX Comply",
        "tagline": "Nigeria Data Protection Act (NDPA) Readiness & Technical Safeguards",
        "short_desc": "Structure your personal data inventories, prepare mandatory technical safeguards, and align operations with the NDPA 2023 ahead of annual statutory filings.",
        "badge": "Regulatory Compliance",
        "icon": "clipboard-check",
        "target_audience": "Fintech platforms, payment processors, insurance and pension managers, private hospitals, private schools, and consumer-facing SMEs processing personal records in Nigeria.",
        "problem_statement": (
            "The Nigeria Data Protection Act (NDPA) 2023 requires organizations processing personal data to maintain strict data protection standards, "
            "document technical safeguards, and file annual statutory compliance audit returns. Non-compliance exposes leadership to regulatory "
            "scrutiny, enforcement orders, public notices, and customer trust loss. Many organizations lack a structured data inventory, "
            "documented incident response procedures, or dedicated privacy expertise to navigate regulatory expectations."
        ),
        "deliverables": [
            "Comprehensive personal-data mapping and processing inventory across customer, employee, and partner touchpoints.",
            "NDPA readiness gap analysis identifying administrative, physical, and technical compliance shortcomings.",
            "Custom Incident Response and Data Breach Notification Plan compliant with statutory disclosure windows.",
            "Technical safeguards evaluation (encryption in transit and at rest, access controls, data retention timelines).",
            "DPO-as-a-Service support: advisory guidance for your designated Data Protection Officer on internal policies and data subject requests.",
            "Filing coordination: structured handoff of your compliance documentation to a licensed Data Protection Compliance Organisation (DPCO) for formal filing.",
        ],
        "dpco_notice": _build_dpco_notice(),
        "engagement_steps": [
            {
                "step": "01",
                "title": "Data Inventory & Gap Assessment",
                "desc": "We review how personal data enters, moves through, and is stored across your databases, software applications, and physical records.",
            },
            {
                "step": "02",
                "title": "Safeguards & Policy Formulation",
                "desc": "We help draft your breach response plan, subject access request workflows, internal privacy notices, and technical encryption controls.",
            },
            {
                "step": "03",
                "title": "Technical Safeguards Handoff",
                "desc": _build_dpco_step_desc(),
            },
        ],
        "not_included": [
            "Direct statutory filing fees assessed by the Nigeria Data Protection Commission (NDPC).",
            "Independent filing or issuance of statutory DPCO audit returns (under the NDPA, annual Compliance Audit Returns must be filed through a licensed DPCO; ADX Group is not a DPCO and does not file them).",
            "Legal representation in court or formal regulatory litigation.",
        ],
        "timeline": get_offer_timeline("comply"),
        "pricing": {"NGN": get_offer_price("comply", "NGN"), "USD": get_offer_price("comply", "USD")},
        "cta_label": "Schedule an NDPA Readiness Review",
        "cta_url": get_booking_url(),
        "meta_title": "ADX Comply | NDPA Compliance & Readiness Engineering Nigeria",
        "meta_description": "Prepare your organization for NDPA 2023 compliance. Data mapping, breach plans, technical safeguards, and licensed DPCO filing coordination in Nigeria.",
        "seo_keywords": "NDPA compliance Nigeria, data protection compliance for fintech Nigeria, NDPC audit readiness, DPCO partner Abuja",
    },
    "resilience": {
        "slug": "resilience",
        "name": "ADX Resilience",
        "tagline": "Tested Backups, Uptime Monitoring & Managed Security Retainer",
        "short_desc": "Protect critical databases against ransomware and infrastructure failures with verified encrypted restore drills, active monitoring, and priority incident support.",
        "badge": "Operational Continuity",
        "icon": "server",
        "target_audience": "Companies with proprietary customer databases, payment ledgers, production ERP systems, or critical infrastructure where prolonged downtime causes catastrophic financial loss.",
        "problem_statement": (
            "Most organizations discover their backups are corrupted, unencrypted, or incomplete only after a ransomware "
            "infection or database server crash occurs. Having an unverified backup script is not a recovery plan. "
            "Encrypted backups do not guarantee restores; recovery must be actively validated through scheduled restore tests with objectives defined per engagement."
        ),
        "deliverables": [
            "Automated, AES-256 encrypted off-site backup architecture isolated in immutable cloud storage.",
            "Scheduled simulated recovery drills: full restore from cold storage to validate recovery time (RTO) and recovery point (RPO) objectives defined for each engagement.",
            "Perimeter health, SSL certificate expiration, and uptime monitoring with instant alerting to your engineering team.",
            "Documented Disaster Recovery and Incident Response runbooks tailored to your server environment.",
            "Emergency recovery assistance: priority engineering support during unexpected server failures or data corruption events.",
            "Quarterly security review and configuration drift inspection across cloud and database assets.",
        ],
        "engagement_steps": [
            {
                "step": "01",
                "title": "Backup & Architecture Review",
                "desc": "We inspect current database snapshot mechanisms, storage locations, encryption keys, and recovery objectives.",
            },
            {
                "step": "02",
                "title": "Automated Backup & Alerting Setup",
                "desc": "We configure scheduled encrypted snapshots, configure separate access controls, and wire uptime monitors to team notification channels.",
            },
            {
                "step": "03",
                "title": "Recovery Verification Drill",
                "desc": "We execute a sandbox restore drill to validate database integrity, measure actual recovery time against objectives, and sign off on operational runbooks.",
            },
        ],
        "not_included": [
            "Guarantees of zero-loss recovery without agreed client-side storage architecture.",
            "Third-party cloud storage fees (e.g., AWS S3 or Azure Blob storage accounts maintained by client).",
            "Re-writing application codebase logic unrelated to database connection pooling or persistence.",
            "Hardware repairs for physical on-premise servers (cloud and virtualized environments only).",
        ],
        "timeline": get_offer_timeline("resilience"),
        "pricing": {"NGN": get_offer_price("resilience", "NGN"), "USD": get_offer_price("resilience", "USD")},
        "cta_label": "Book a Resilience Consultation",
        "cta_url": get_booking_url(),
        "meta_title": "ADX Resilience | Tested Backups & Disaster Recovery Nigeria",
        "meta_description": "Ensure business continuity with tested encrypted backups, restore drills, uptime monitoring, and managed disaster recovery retainers by ADX Group.",
        "seo_keywords": "disaster recovery Nigeria, cloud backup drills Lagos, database ransomware protection, uptime monitoring Abuja",
    },
    "ai-automation": {
        "slug": "ai-automation",
        "name": "ADX AI and Automation",
        "tagline": "Private Document Search, Workflow Automation & Agent Security Rules",
        "short_desc": "Deploy private AI assistants that search internal company knowledge without leaking IP to public LLMs, backed by strict approval boundaries and audit logging.",
        "badge": "Planned / On Request &bull; Secure Enterprise AI",
        "icon": "cpu",
        "target_audience": "Professional services firms, compliance teams, customer support centers, and technical operators seeking to automate repetitive tasks safely.",
        "problem_statement": (
            "Employees are increasingly feeding sensitive company policies, client files, and confidential code into public "
            "AI tools without oversight, creating significant intellectual property leakage risks. Meanwhile, poorly "
            "governed autonomous agents can execute unauthorized actions, corrupt database records, or fail to log decisions. "
            "Organizations need productivity automation with strict boundaries: private knowledge retrieval, human approval gates, and tamper-evident audit trails."
        ),
        "deliverables": [
            "Private Retrieval-Augmented Generation (RAG) assistant indexing internal policy PDFs, manuals, and records with zero public model training.",
            "AI agent access boundary definition: strict whitelisting of which internal systems and databases the agent can query.",
            "Human-in-the-loop approval workflows for high-consequence actions (e.g., refunds, database mutations, external emails).",
            "Comprehensive audit logging: full timestamped records of every user query, agent tool call, and generated response.",
            "Prompt injection defense: defensive system instructions and input sanitizers mitigating OWASP LLM Top 10 vulnerabilities.",
            "Model Context Protocol (MCP) tool integration: connecting private models securely to existing internal REST APIs.",
        ],
        "engagement_steps": [
            {
                "step": "01",
                "title": "Use-Case & Data Boundary Scope",
                "desc": "We identify repetitive workflows, inventory internal reference documents, and define strict data boundaries.",
            },
            {
                "step": "02",
                "title": "Pipeline Engineering & Guardrails",
                "desc": "We build vector embeddings, configure private retrieval, connect authorized APIs, and implement human approval gates.",
            },
            {
                "step": "03",
                "title": "Security Review & Staff Onboarding",
                "desc": "We test prompt-injection resilience, verify audit logging pipelines, and train team members on safe daily operation.",
            },
        ],
        "not_included": [
            "Training foundational large language models from scratch (we implement private retrieval and orchestration).",
            "Unrestricted autonomous write access to production financial ledgers without human authorization gates.",
            "Third-party LLM API consumption token costs (billed directly by model providers).",
        ],
        "timeline": get_offer_timeline("ai-automation"),
        "pricing": {"NGN": get_offer_price("ai-automation", "NGN"), "USD": get_offer_price("ai-automation", "USD")},
        "cta_label": "Explore AI Automation Architecture",
        "cta_url": get_booking_url(),
        "meta_title": "ADX AI and Automation | Private AI & Workflow Automation Nigeria",
        "meta_description": "Private document-search assistants, workflow automation, and agent security rules with zero data retention. Engineered securely in Nigeria by ADX Group.",
        "seo_keywords": "private AI assistant Nigeria, enterprise workflow automation Lagos, secure RAG architecture, AI guardrails Abuja",
    },
}

# Sectors for Task B ("Who we help")
SECTORS_LIST = [
    {
        "name": "Fintech & Payments",
        "icon": "credit-card",
        "risk": "Targeted by sophisticated executive impersonation, payment redirection fraud, and stringent regulatory reporting mandates.",
        "outcome": "Hardened DMARC anti-spoofing policies, enforced MFA controls, and audit-ready data safeguards that satisfy partner banks and regulators.",
    },
    {
        "name": "Insurance & Pension Managers",
        "icon": "shield-check",
        "risk": "Custodian of sensitive identity records, policy archives, and long-term financial commitments subject to strict NDPA data handling.",
        "outcome": "Systematic personal-data mapping, audited retention schedules, and licensed DPCO filing coordination that protects customer records.",
    },
    {
        "name": "Clinics & Healthcare Providers",
        "icon": "activity",
        "risk": "Patient health records and diagnostic archives are vulnerable to ransomware attacks, unencrypted exposure, and insider leakage.",
        "outcome": "Encrypted off-site backups with tested recovery drills, role-based record access, and documented medical breach response plans.",
    },
    {
        "name": "Schools & EdTech Institutions",
        "icon": "book-open",
        "risk": "Student identity records, parental financial data, and exam ledgers are frequently managed across fragmented, unmonitored portals.",
        "outcome": "Centralized identity governance, secure staff offboarding procedures, and verifiable NDPA consent frameworks for student records.",
    },
    {
        "name": "Logistics & Consumer SMEs",
        "icon": "truck",
        "risk": "High volume of customer shipping addresses, phone numbers, and transactional receipts handled on insecure email and chat channels.",
        "outcome": "Turnkey perimeter defense, secure operational communications, and clear data minimization safeguards scaled for growing teams.",
    },
]

# 10 Questions for Task C ("Free NDPA and Security Readiness Check")
READINESS_QUESTIONS = [
    {
        "id": "q1",
        "category": "Data Governance",
        "question": "Does your organization maintain a documented inventory of all personal customer and employee data collected, stored, and shared?",
        "tip": "NDPA Section 24 requires clear records of data categories, processing purposes, and storage locations.",
    },
    {
        "id": "q2",
        "category": "Data Governance",
        "question": "Have you formally designated an internal or external Data Protection Officer (DPO) responsible for privacy compliance?",
        "tip": "Covered organizations processing significant data volumes must designate a qualified DPO.",
    },
    {
        "id": "q3",
        "category": "Incident Response",
        "question": "Do you have a written, actionable Data Breach Response Plan with steps to notify authorities within statutory timelines?",
        "tip": "Under the NDPA, reportable personal data breaches must be notified to the NDPC within 72 hours.",
    },
    {
        "id": "q4",
        "category": "Identity Security",
        "question": "Is Multi-Factor Authentication (MFA) strictly enforced for all corporate email accounts and administrative cloud portals?",
        "tip": "MFA blocks over 99% of automated credential stuffing and phishing takeovers.",
    },
    {
        "id": "q5",
        "category": "Data Resilience",
        "question": "Are critical databases backed up off-site with encryption, and have you conducted a live restoration drill in the last 6 months?",
        "tip": "An untested backup is not a recovery plan. Drills verify data can actually be restored after corruption.",
    },
    {
        "id": "q6",
        "category": "Vendor Risk",
        "question": "Do you require written Data Processing Agreements (DPAs) or security commitments from all third-party software vendors?",
        "tip": "Organizations remain responsible for personal data mishandled by external SaaS and cloud processors.",
    },
    {
        "id": "q7",
        "category": "Email Security",
        "question": "Has your domain published active SPF, DKIM, and DMARC records to prevent external attackers from spoofing your corporate email?",
        "tip": "Unenforced email authentication leaves customers and staff exposed to forged executive emails.",
    },
    {
        "id": "q8",
        "category": "Staff Awareness",
        "question": "Have your employees completed cybersecurity hygiene and data protection awareness training within the past 12 months?",
        "tip": "Human error is the leading vector for phishing and accidental data disclosures.",
    },
    {
        "id": "q9",
        "category": "AI & Tool Governance",
        "question": "Does your company have documented rules restricting staff from uploading confidential data or customer files into public AI tools?",
        "tip": "Public LLMs can ingest submitted text for retraining, leaking proprietary IP and customer secrets.",
    },
    {
        "id": "q10",
        "category": "Access Management",
        "question": "Do you have an enforced offboarding checklist that revokes email, VPN, and database access immediately upon employee departure?",
        "tip": "Stale credentials from former staff represent a top vector for unauthorized perimeter entry.",
    },
]
