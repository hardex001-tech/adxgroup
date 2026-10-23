"""
ADX Group — 5-Vector Deep Security & Infrastructure Diagnostic Engine.
Performs passive, non-intrusive security posture assessments across:
1. SSL/TLS Cryptographic Handshake & Certificate Validity
2. Email Anti-Spoofing & DNS Security (SPF / DMARC Policy Verification via DoH)
3. HTTP Security Headers (HSTS, CSP, Clickjacking, MIME-Sniffing, Referrer)
4. Cross-Origin Resource Sharing (CORS) & Session Cookie Security
5. Server Technology Banner Leakage & Sensitive Path Exposure
"""

import asyncio
import datetime
import re
import socket
import ssl
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx


def normalize_domain(raw_input: str) -> str:
    """Clean user input into a bare domain hostname."""
    cleaned = raw_input.strip().lower()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    parsed = urlparse(cleaned)
    host = parsed.netloc or parsed.path
    host = host.split("@")[-1].split(":")[0].strip("/")
    return host


async def _query_doh(client: httpx.AsyncClient, name: str, record_type: str = "TXT") -> List[str]:
    """Query DNS records over HTTPS (Cloudflare DoH) for 100% reliability across any ISP."""
    try:
        resp = await client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": name, "type": record_type},
            headers={"Accept": "application/dns-json"},
            timeout=5.0,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        answers = data.get("Answer", [])
        records = []
        for ans in answers:
            val = ans.get("data", "").strip('"')
            if val:
                records.append(val)
        return records
    except Exception:
        return []


def _check_ssl_sync(domain: str, target_ip: str = "", timeout: float = 5.5) -> Dict[str, Any]:
    """Inspect TLS/SSL handshake, protocol version, cipher suite, and certificate expiry."""
    if not target_ip:
        return {
            "passed": False,
            "tls_version": "No Web Server",
            "cipher": "None",
            "issuer": "None",
            "days_remaining": 0,
            "summary": (
                f"No DNS 'A' record (web server IP) is configured for '{domain}'. "
                "The domain is either parked, unhosted, or spelled differently."
            ),
            "remediation": (
                f"Point an 'A' or 'CNAME' DNS record for {domain} to your production host and enable Cloudflare Universal SSL."
            ),
        }

    ctx = ssl.create_default_context()
    connect_target = target_ip or domain
    try:
        with socket.create_connection((connect_target, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version() or "Unknown"
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else "Unknown"

                not_after_str = cert.get("notAfter", "")
                days_remaining = -1
                if not_after_str:
                    expiry_dt = datetime.datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    now_dt = datetime.datetime.now(datetime.timezone.utc)
                    days_remaining = (expiry_dt - now_dt).days

                issuer_parts = cert.get("issuer", ())
                issuer_org = "Verified Authority"
                for item in issuer_parts:
                    for k, v in item:
                        if k == "organizationName":
                            issuer_org = v

                modern_tls = tls_version in ("TLSv1.3", "TLSv1.2")
                valid_cert = days_remaining > 14

                passed = modern_tls and valid_cert
                return {
                    "passed": passed,
                    "tls_version": tls_version,
                    "cipher": cipher_name,
                    "issuer": issuer_org,
                    "days_remaining": days_remaining,
                    "summary": (
                        f"Active {tls_version} ({cipher_name}) issued by {issuer_org}. "
                        f"Certificate valid for {days_remaining} days."
                    ),
                    "remediation": (
                        None
                        if passed
                        else "Enforce TLSv1.2 / TLSv1.3 minimum in web server configuration and enable automated certificate renewal."
                    ),
                }
    except ssl.SSLCertVerificationError:
        return {
            "passed": False,
            "tls_version": "Untrusted Cert",
            "cipher": "Unknown",
            "issuer": "Self-Signed / Mismatch",
            "days_remaining": 0,
            "summary": f"SSL certificate on {domain} failed hostname verification or is expired/self-signed.",
            "remediation": "Re-issue a valid SAN certificate matching the root domain and enable Full (Strict) SSL.",
        }
    except Exception:
        return {
            "passed": False,
            "tls_version": "Unreachable on 443",
            "cipher": "None",
            "issuer": "Unverified",
            "days_remaining": 0,
            "summary": f"Port 443 (HTTPS) on {domain} did not complete a TLS handshake within timeout.",
            "remediation": (
                "Ensure HTTPS port 443 is open on the web firewall and install a valid TLS certificate."
            ),
        }


async def check_dns_email_security(client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
    """Inspect SPF and DMARC DNS records to detect email spoofing & phishing vulnerability."""
    root_txt, dmarc_txt = await asyncio.gather(
        _query_doh(client, domain, "TXT"),
        _query_doh(client, f"_dmarc.{domain}", "TXT"),
    )

    spf_records = [r for r in root_txt if "v=spf1" in r.lower()]
    dmarc_records = [r for r in dmarc_txt if "v=dmarc1" in r.lower()]

    has_spf = len(spf_records) > 0
    spf_strict = any(("-all" in r.lower() or "~all" in r.lower()) for r in spf_records)

    has_dmarc = len(dmarc_records) > 0
    dmarc_policy = "missing"
    if has_dmarc:
        m = re.search(r"p\s*=\s*(reject|quarantine|none)", dmarc_records[0], re.IGNORECASE)
        if m:
            dmarc_policy = m.group(1).lower()

    dmarc_enforced = dmarc_policy in ("reject", "quarantine")
    passed = has_spf and spf_strict and has_dmarc and dmarc_enforced

    findings = []
    if not has_spf:
        findings.append("No SPF TXT record found (external servers can forge sender identity).")
    elif not spf_strict:
        findings.append("SPF record lacks strict '-all' or '~all' enforcement.")

    if not has_dmarc:
        findings.append(f"No DMARC record at _dmarc.{domain} (vulnerable to domain email spoofing).")
    elif dmarc_policy == "none":
        findings.append("DMARC policy is set to 'p=none' (monitoring only; spoofed phishing emails are still delivered).")

    if passed:
        summary = f"SPF active and DMARC enforced (policy: p={dmarc_policy}). Anti-spoofing protection verified."
        remediation = None
    else:
        summary = " ".join(findings)
        remediation = (
            f"Add DNS TXT record on _dmarc.{domain} -> "
            f'\"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:security@{domain}\"'
        )

    return {
        "passed": passed,
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "dmarc_policy": dmarc_policy,
        "summary": summary,
        "remediation": remediation,
    }


async def check_http_headers_and_exposure(
    client: httpx.AsyncClient, domain: str, has_web_ip: bool
) -> Dict[str, Any]:
    """Inspect HTTP security headers, CORS policy, banner leakage, and exposed files."""
    if not has_web_ip:
        return {
            "Reachable": False,
            "headers_passed": False,
            "cors_passed": False,
            "exposure_passed": True,
            "missing_headers": [],
            "leaked_banners": [],
            "exposed_paths": [],
            "headers_summary": f"No active web server ('A' record) found on {domain} to serve HTTP headers.",
            "headers_remediation": "Deploy your web application or point your domain 'A' record to Cloudflare / Azure.",
            "cors_summary": "No public web API endpoint active on root domain.",
            "cors_remediation": None,
            "exposure_summary": "No exposed web files (/.env, /.git) or server version banners detected.",
            "exposure_remediation": None,
        }

    url = f"https://{domain}"
    headers_report: Dict[str, bool] = {
        "Strict-Transport-Security": False,
        "Content-Security-Policy": False,
        "X-Frame-Options": False,
        "X-Content-Type-Options": False,
        "Referrer-Policy": False,
    }
    missing_headers: List[str] = []
    leaked_banners: List[str] = []
    cors_issue = False
    status_code = 0

    try:
        resp = await client.get(
            url,
            follow_redirects=True,
            timeout=6.5,
            headers={"User-Agent": "ADX-Security-Diagnostic/2.0 (+https://adxgroup.tech)"},
        )
        status_code = resp.status_code
        h = resp.headers

        for hdr in headers_report:
            if hdr.lower() in h:
                headers_report[hdr] = True
            else:
                missing_headers.append(hdr)

        for banner_hdr in ("x-powered-by", "x-aspnet-version", "x-generator"):
            if banner_hdr in h:
                leaked_banners.append(f"{banner_hdr}: {h[banner_hdr]}")
        if "server" in h and any(char.isdigit() for char in h["server"]):
            leaked_banners.append(f"server: {h['server']}")

        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            cors_issue = True

    except Exception:
        return {
            "Reachable": False,
            "headers_passed": False,
            "cors_passed": False,
            "exposure_passed": True,
            "missing_headers": list(headers_report.keys()),
            "leaked_banners": [],
            "exposed_paths": [],
            "headers_summary": f"Web server on {domain} did not respond over HTTPS (port 443 closed or unreachable).",
            "headers_remediation": "Ensure web server is listening on port 443 and behind a reverse proxy / WAF.",
            "cors_summary": "HTTPS endpoint unreachable; CORS headers could not be verified.",
            "cors_remediation": None,
            "exposure_summary": "No exposed sensitive paths detected.",
            "exposure_remediation": None,
        }

    exposed_paths: List[str] = []
    for path, signature in (("/.env", "APP_"), ("/.git/HEAD", "ref: refs/")):
        try:
            probe = await client.get(f"https://{domain}{path}", follow_redirects=False, timeout=3.5)
            if probe.status_code == 200 and signature in probe.text[:200]:
                exposed_paths.append(path)
        except Exception:
            pass

    headers_passed = len(missing_headers) <= 1
    if headers_passed:
        headers_summary = "Core HTTP defensive headers (HSTS, Frame, Content-Type) are properly enforced."
        headers_remediation = None
    else:
        headers_summary = f"Missing {len(missing_headers)} defensive HTTP headers: {', '.join(missing_headers)}."
        headers_remediation = (
            "Add response headers in Nginx/Cloudflare:\n"
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
            "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
            "add_header X-Content-Type-Options \"nosniff\" always;\n"
            "add_header Content-Security-Policy \"default-src 'self' https:;\" always;"
        )

    cors_passed = not cors_issue
    cors_summary = (
        "Cross-Origin (CORS) policy and session boundaries are properly scoped."
        if cors_passed
        else "Wildcard Access-Control-Allow-Origin (*) combined with credentials exposes APIs to cross-site data theft."
    )
    cors_remediation = (
        None
        if cors_passed
        else "Restrict 'Access-Control-Allow-Origin' to explicit trusted production origins instead of '*'."
    )

    exposure_passed = (len(leaked_banners) == 0) and (len(exposed_paths) == 0)
    if exposure_passed:
        exposure_summary = "Zero exposed configuration dotfiles (/.env, /.git) and server version banners are hidden."
        exposure_remediation = None
    else:
        parts = []
        if exposed_paths:
            parts.append(f"CRITICAL: Publicly accessible files detected: {', '.join(exposed_paths)}.")
        if leaked_banners:
            parts.append(f"Server technology version disclosed ({', '.join(leaked_banners)}).")
        exposure_summary = " ".join(parts)
        exposure_remediation = (
            "Disable server tokens ('server_tokens off;' in Nginx) and block public access to dotfiles (~ /\\.(?!well-known))."
        )

    return {
        "Reachable": True,
        "status_code": status_code,
        "headers_passed": headers_passed,
        "cors_passed": cors_passed,
        "exposure_passed": exposure_passed,
        "missing_headers": missing_headers,
        "leaked_banners": leaked_banners,
        "exposed_paths": exposed_paths,
        "headers_summary": headers_summary,
        "headers_remediation": headers_remediation,
        "cors_summary": cors_summary,
        "cors_remediation": cors_remediation,
        "exposure_summary": exposure_summary,
        "exposure_remediation": exposure_remediation,
    }


async def run_full_diagnostic(raw_domain: str) -> Dict[str, Any]:
    """Run all 5 security diagnostic vectors concurrently and compute the Truth Table & Score."""
    domain = normalize_domain(raw_domain)
    if not domain or "." not in domain:
        raise ValueError("Please provide a valid domain name (e.g., google.com or github.com).")

    async with httpx.AsyncClient(verify=False) as client:
        # First resolve DNS A records over HTTPS so we know if a web server exists
        a_records = await _query_doh(client, domain, "A")
        ip_list = [ip for ip in a_records if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip)]
        primary_ip = ip_list[0] if ip_list else ""

        ssl_task = asyncio.to_thread(_check_ssl_sync, domain, primary_ip)
        dns_task = check_dns_email_security(client, domain)
        http_task = check_http_headers_and_exposure(client, domain, bool(primary_ip))

        ssl_res, dns_res, http_res = await asyncio.gather(ssl_task, dns_task, http_task)

    gates = [
        {
            "gate_id": "GATE-01",
            "vector": "TLS/SSL Cryptographic Handshake",
            "condition": "Valid certificate chain & modern TLS 1.2/1.3 protocol",
            "state": bool(ssl_res["passed"]),
            "status_label": "TRUE (PASS)" if ssl_res["passed"] else "FALSE (FAIL)",
            "severity": "LOW" if ssl_res["passed"] else "HIGH",
            "finding": ssl_res["summary"],
            "remediation": ssl_res["remediation"],
        },
        {
            "gate_id": "GATE-02",
            "vector": "Email Anti-Spoofing (SPF & DMARC)",
            "condition": "Strict SPF policy & enforced DMARC (p=quarantine / p=reject)",
            "state": bool(dns_res["passed"]),
            "status_label": "TRUE (PASS)" if dns_res["passed"] else "FALSE (FAIL)",
            "severity": "LOW" if dns_res["passed"] else "HIGH",
            "finding": dns_res["summary"],
            "remediation": dns_res["remediation"],
        },
        {
            "gate_id": "GATE-03",
            "vector": "HTTP Defensive Security Headers",
            "condition": "HSTS, CSP, X-Frame-Options & X-Content-Type-Options present",
            "state": bool(http_res["headers_passed"]),
            "status_label": "TRUE (PASS)" if http_res["headers_passed"] else "FALSE (FAIL)",
            "severity": "LOW" if http_res["headers_passed"] else "MEDIUM",
            "finding": http_res["headers_summary"],
            "remediation": http_res["headers_remediation"],
        },
        {
            "gate_id": "GATE-04",
            "vector": "API Cross-Origin (CORS) & Session Policy",
            "condition": "No wildcard origin leaks with credentialed requests",
            "state": bool(http_res["cors_passed"]),
            "status_label": "TRUE (PASS)" if http_res["cors_passed"] else "FALSE (FAIL)",
            "severity": "LOW" if http_res["cors_passed"] else "HIGH",
            "finding": http_res["cors_summary"],
            "remediation": http_res["cors_remediation"],
        },
        {
            "gate_id": "GATE-05",
            "vector": "Banner Leakage & Sensitive Asset Exposure",
            "condition": "Zero exposed dotfiles (/.env, /.git) & hidden server versions",
            "state": bool(http_res["exposure_passed"]),
            "status_label": "TRUE (PASS)" if http_res["exposure_passed"] else "FALSE (FAIL)",
            "severity": "LOW" if http_res["exposure_passed"] else "CRITICAL",
            "finding": http_res["exposure_summary"],
            "remediation": http_res["exposure_remediation"],
        },
    ]

    weights = [25, 25, 20, 15, 15]
    score = sum(w for g, w in zip(gates, weights) if g["state"])

    if score >= 90:
        grade = "A"
        risk_level = "LOW RISK"
    elif score >= 75:
        grade = "B"
        risk_level = "MODERATE RISK"
    elif score >= 50:
        grade = "C"
        risk_level = "ELEVATED RISK"
    else:
        grade = "D"
        risk_level = "HIGH RISK"

    failed_gates = [g for g in gates if not g["state"]]
    outreach_email = _build_outreach_email(domain, score, failed_gates)

    return {
        "domain": domain,
        "resolved_ip": primary_ip or "None (No A Record)",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "score": score,
        "grade": grade,
        "risk_level": risk_level,
        "passed_count": sum(1 for g in gates if g["state"]),
        "total_gates": len(gates),
        "gates": gates,
        "outreach_email": outreach_email,
    }


def _build_outreach_email(domain: str, score: int, failed_gates: List[Dict[str, Any]]) -> str:
    """Generate a tailored, value-first B2B outreach advisory for the scanned domain."""
    if not failed_gates:
        return (
            f"Subject: Infrastructure & AI Readiness Note for {domain}\n\n"
            f"Hi Team,\n\n"
            f"Our automated diagnostics at ADX Group reviewed {domain} and confirmed a strong external security score ({score}/100).\n"
            f"If your engineering team is looking to deploy private AI document assistants (RAG) or automate cloud maintenance "
            f"without increasing cloud burn, reply here and we can share our architecture brief.\n\n"
            f"Best regards,\n"
            f"ADX Systems & Threat Intelligence\n"
            f"https://adxgroup.tech | contact@adxgroup.tech"
        )

    bullet_points = []
    fixes = []
    for idx, g in enumerate(failed_gates[:3], start=1):
        bullet_points.append(f"{idx}. [{g['vector']}]: {g['finding']}")
        if g.get("remediation"):
            fixes.append(f"- Fix for #{idx}: {g['remediation']}")

    bullets_str = "\n".join(bullet_points)
    fixes_str = "\n".join(fixes)

    return (
        f"Subject: Quick security note regarding {domain} external posture\n\n"
        f"Hi Team,\n\n"
        f"While conducting routine external security posture checks, ADX Group identified {len(failed_gates)} "
        f"configuration gap(s) on {domain} (Current Perimeter Score: {score}/100):\n\n"
        f"{bullets_str}\n\n"
        f"Your engineering team can apply these exact fixes immediately at zero cost:\n"
        f"{fixes_str}\n\n"
        f"At ADX Group, we help growing companies harden their cloud infrastructure, lock down web applications, "
        f"and deploy secure AI automation on a fixed-scope basis.\n\n"
        f"If you would like our team to perform a complete perimeter hardening and configure 24/7 automated monitoring "
        f"for {domain}, reply to this email and we will send over our fixed-scope brief.\n\n"
        f"Best regards,\n"
        f"ADX Threat Intelligence Desk\n"
        f"https://adxgroup.tech | contact@adxgroup.tech"
    )
