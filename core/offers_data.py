"""
Detailed content models and specifications for ADX Group's 4 core solution offers.
"""

from core.offers_config import (
    PRICING_CONFIG,
    TIMELINE_CONFIG,
    PARTNER_DPCO_NAME,
    BOOKING_URL,
)

OFFERS_DICT = {
    "shield": {
        "slug": "shield",
        "name": "ADX Shield",
        "tagline": "Email Fraud, Identity Security & Perimeter Defense",
        "short_desc": "Protect executive communications against business email compromise (BEC), enforce identity controls across your team, and audit third-party vendor risks.",
        "badge": "Email & Identity Defense",
        "icon": "shield",
        "target_audience": "Fintech teams, high-growth startups, legal practices, and corporate finance departments handling sensitive fund transfers, executive approvals, or customer accounts.",
        "problem_statement": (
            "Over 90% of targeted corporate fraud starts with email impersonation and compromised credentials. "
            "When domain authentication is not strictly enforced, malicious actors can send forged payment instructions "
            "that appear to originate directly from your company's domain. Combined with missing multi-factor authentication "
            "and unmanaged vendor access, your perimeter remains exposed to account takeovers and financial redirection."
        ),
        "deliverables": [
            "Complete SPF, DKIM, and DMARC record generation, alignment, and staged enforcement rollout (monitoring to quarantine/reject).",
            "Business email compromise (BEC) protection audit across your email provider (Google Workspace, Microsoft 365, or Zoho).",
            "Identity security and mandatory Multi-Factor Authentication (MFA) rollout guide for all team accounts.",
            "User access review and role-based permissions audit across cloud portals and administrative dashboards.",
            "Standardized employee offboarding security checklist to immediately revoke access tokens, API keys, and device sessions.",
            "Basic third-party and vendor risk assessment checklist to evaluate external SaaS tools handling corporate data.",
        ],
        "engagement_steps": [
            {
                "step": "01",
                "title": "Discovery & Perimeter Audit",
                "desc": "We inspect your domain DNS records, current email deliverability headers, active user directories, and external vendor exposure.",
            },
            {
                "step": "02",
                "title": "Staged Technical Hardening",
                "desc": "We implement DKIM signing, align SPF sources, roll out enforced MFA policies, and advance DMARC policy rules without disrupting legitimate mail.",
            },
            {
                "step": "03",
                "title": "Verification & Operating Playbook",
                "desc": "We test authentication headers across receiving providers, hand over user access procedures and offboarding checklists, and conduct an executive walkthrough.",
            },
        ],
        "not_included": [
            "24/7 continuous SOC monitoring or managed detection and response (available under ADX Resilience retainer).",
            "Active penetration testing or adversary simulation beyond authentication and identity configuration.",
            "Provisioning or direct licensing costs of third-party identity providers (e.g., Okta, Google Workspace licenses).",
        ],
        "timeline": TIMELINE_CONFIG["shield"],
        "pricing": PRICING_CONFIG["shield"],
        "cta_label": "Book an Email & Identity Review",
        "cta_url": BOOKING_URL,
        "meta_title": "ADX Shield | Email Fraud, DMARC & Identity Defense Nigeria",
        "meta_description": "Protect your domain against executive spoofing, BEC fraud, and credential compromise with ADX Shield. Staged DMARC, MFA rollout, and vendor risk checks.",
        "seo_keywords": "DMARC setup Nigeria, business email fraud protection Nigeria, BEC defense Lagos, SPF DKIM enforcement",
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
        "dpco_notice": (
            f"Statutory Notice: Under the Nigeria Data Protection Act 2023, annual Compliance Audit Returns (CAR) "
            f"must be filed with the Nigeria Data Protection Commission (NDPC) through a licensed Data Protection "
            f"Compliance Organisation (DPCO). ADX Group provides technical audit, data mapping, and readiness engineering, "
            f"and works in direct collaboration with our licensed DPCO partner, {PARTNER_DPCO_NAME}, for formal statutory filing. "
            f"ADX Group is an engineering consultancy and does not independently issue statutory audit certificates."
        ),
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
                "title": "DPCO Audit Filing Handoff",
                "desc": f"We assemble the technical audit documentation and coordinate directly with {PARTNER_DPCO_NAME} for formal filing with the NDPC.",
            },
        ],
        "not_included": [
            "Direct statutory filing fees assessed by the Nigeria Data Protection Commission (NDPC).",
            "Independent issuance of DPCO audit seals (all statutory returns are filed by our licensed DPCO partner).",
            "Legal representation in court or formal regulatory litigation.",
        ],
        "timeline": TIMELINE_CONFIG["comply"],
        "pricing": PRICING_CONFIG["comply"],
        "cta_label": "Schedule an NDPA Readiness Review",
        "cta_url": BOOKING_URL,
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
            "Without documented restore drills, automated latency and health alerting, and an on-call response team, "
            "an unexpected outage can halt business operations for days or weeks."
        ),
        "deliverables": [
            "Automated, AES-256 encrypted off-site backup architecture isolated in immutable cloud storage.",
            "Semi-annual simulated recovery drills: full restore from cold storage to verify recovery time (RTO) and data point (RPO) objectives.",
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
                "title": "Live Recovery Verification Drill",
                "desc": "We execute a sandbox restore drill to verify database integrity, measure actual recovery time, and sign off on operational runbooks.",
            },
        ],
        "not_included": [
            "Third-party cloud storage fees (e.g., AWS S3 or Azure Blob storage accounts maintained by client).",
            "Re-writing application codebase logic unrelated to database connection pooling or persistence.",
            "Hardware repairs for physical on-premise servers (cloud and virtualized environments only).",
        ],
        "timeline": TIMELINE_CONFIG["resilience"],
        "pricing": PRICING_CONFIG["resilience"],
        "cta_label": "Book a Resilience Consultation",
        "cta_url": BOOKING_URL,
        "meta_title": "ADX Resilience | Tested Backups & Disaster Recovery Nigeria",
        "meta_description": "Ensure business continuity with tested encrypted backups, restore drills, uptime monitoring, and managed disaster recovery retainers by ADX Group.",
        "seo_keywords": "disaster recovery Nigeria, cloud backup drills Lagos, database ransomware protection, uptime monitoring Abuja",
    },
    "ai-automation": {
        "slug": "ai-automation",
        "name": "ADX AI and Automation",
        "tagline": "Private Document Search, Workflow Automation & Agent Security Rules",
        "short_desc": "Deploy private AI assistants that search internal company knowledge without leaking IP to public LLMs, backed by strict approval boundaries and audit logging.",
        "badge": "Secure Enterprise AI",
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
        "timeline": TIMELINE_CONFIG["ai-automation"],
        "pricing": PRICING_CONFIG["ai-automation"],
        "cta_label": "Explore AI Automation Architecture",
        "cta_url": BOOKING_URL,
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
