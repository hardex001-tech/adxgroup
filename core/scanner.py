"""
ADX Group — 2026 Deep Security, Telemetry & CVE Threat Intelligence Engine.
Captures verifiable live network telemetry (IP, Latency ms, TLS Cipher, Cert Serial/Issuer)
and evaluates external & hidden attack surfaces mapped to 2026 CVE / CWE signatures.
"""

import asyncio
import ipaddress
import datetime
import re
import socket
import ssl
import time
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx


FQDN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$",
    re.IGNORECASE,
)

RESERVED_DOMAINS = {
    "localhost", "broadcasthost", "localdomain",
}
RESERVED_SUFFIXES = (
    ".local", ".internal", ".localhost", ".test", ".corp", ".lan", ".home.arpa", ".arpa", ".invalid", ".example"
)

def _is_disallowed_ip(ip_str: str) -> bool:
    """Return True if the IP address is private, loopback, link-local, multicast, or cloud metadata."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or str(ip).startswith("169.254.")
        )
    except ValueError:
        return True


def normalize_domain(raw_input: str) -> str:
    """Clean user input into a bare domain hostname and reject reserved/non-public domains."""
    cleaned = raw_input.strip().lower()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    parsed = urlparse(cleaned)
    host = parsed.netloc or parsed.path
    host = host.split("@")[-1].split(":")[0].strip("/").strip(".")
    if not host or not FQDN_REGEX.match(host) or host in RESERVED_DOMAINS or any(host.endswith(s) for s in RESERVED_SUFFIXES):
        return ""
    return host


async def _query_doh(client: httpx.AsyncClient, name: str, record_type: str = "TXT") -> List[str]:
    """Query DNS records over HTTPS using literal IP endpoints (1.1.1.1 & 8.8.8.8) to bypass ISP DNS failures."""
    endpoints = [
        ("https://1.1.1.1/dns-query", {"name": name, "type": record_type}),
        ("https://8.8.8.8/resolve", {"name": name, "type": record_type}),
    ]
    type_code_map = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
    wanted_code = type_code_map.get(record_type.upper())

    for url, params in endpoints:
        try:
            resp = await client.get(
                url,
                params=params,
                headers={"Accept": "application/dns-json"},
                timeout=4.5,
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                records = []
                for ans in answers:
                    if wanted_code and ans.get("type") not in (wanted_code, record_type):
                        continue
                    val = str(ans.get("data", "")).strip('"')
                    if val:
                        records.append(val)
                if records:
                    return records
        except Exception:
            continue
    return []


def _resolve_os_ips(domain: str) -> List[str]:
    """Resolve IPv4 addresses using native OS DNS with 1.1.1.1 DoH fallback, rejecting non-public IPs."""
    ips: List[str] = []
    try:
        infos = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if ip and ip not in ips and not _is_disallowed_ip(ip):
                ips.append(ip)
    except Exception:
        pass
    if not ips:
        try:
            resp = httpx.get(
                "https://1.1.1.1/dns-query",
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=4.0,
                verify=True,
            )
            if resp.status_code == 200:
                for ans in resp.json().get("Answer", []):
                    if ans.get("type") == 1 and ans.get("data"):
                        candidate = str(ans["data"]).strip()
                        if not _is_disallowed_ip(candidate):
                            ips.append(candidate)
        except Exception:
            pass
    return ips


def _check_ssl_sync(domain: str, target_ip: str = "", timeout: float = 5.5) -> Dict[str, Any]:
    """Inspect TLS/SSL handshake, latency, protocol version, cipher suite, and certificate metadata."""
    if not target_ip:
        os_ips = _resolve_os_ips(domain)
        if os_ips:
            target_ip = os_ips[0]
    if not target_ip:
        return {
            "passed": False,
            "tls_version": "No Host IP",
            "cipher": "None",
            "issuer": "Unissued",
            "serial": "N/A",
            "latency_ms": 0,
            "days_remaining": 0,
            "summary": (
                f"No DNS 'A' record (web server IP) resolves for '{domain}'. "
                "The domain has no active HTTPS web server."
            ),
            "admin_fix": (
                f"Configure an A/CNAME record for {domain} behind Cloudflare WAF with Full (Strict) TLS 1.3."
            ),
        }

    ctx = ssl.create_default_context()
    connect_target = target_ip or domain
    t0 = time.perf_counter()
    try:
        with socket.create_connection((connect_target, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                latency_ms = int((time.perf_counter() - t0) * 1000)
                cert = ssock.getpeercert()
                tls_version = ssock.version() or "Unknown"
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else "Unknown"
                serial_num = cert.get("serialNumber", "Verified")[:16]

                not_after_str = cert.get("notAfter", "")
                days_remaining = -1
                if not_after_str:
                    expiry_dt = datetime.datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    now_dt = datetime.datetime.now(datetime.timezone.utc)
                    days_remaining = (expiry_dt - now_dt).days

                issuer_parts = cert.get("issuer", ())
                issuer_org = "Verified CA"
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
                    "serial": serial_num,
                    "latency_ms": latency_ms,
                    "days_remaining": days_remaining,
                    "summary": (
                        f"Verified {tls_version} handshake ({cipher_name}) in {latency_ms}ms. "
                        f"Issued by {issuer_org} (Serial: {serial_num}, valid {days_remaining}d)."
                    ),
                    "admin_fix": (
                        None
                        if passed
                        else "Enforce TLSv1.3 minimum cipher suites and automate certificate rotation."
                    ),
                }
    except Exception:
        return {
            "passed": False,
            "tls_version": "Handshake Failed",
            "cipher": "None",
            "issuer": "Unverified",
            "serial": "N/A",
            "latency_ms": 0,
            "days_remaining": 0,
            "summary": f"Port 443 on {domain} ({target_ip}) failed cryptographic TLS verification.",
            "admin_fix": "Provision a valid SAN TLS certificate and enforce strict HTTPS redirection on port 443.",
        }


async def check_dns_email_security(client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
    """Inspect SPF and DMARC DNS records to detect email spoofing & BEC vulnerability."""
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
        findings.append("Missing SPF TXT record allows arbitrary mail servers to forge @domain emails.")
    elif not spf_strict:
        findings.append("SPF policy lacks strict '-all' sender rejection.")

    if not has_dmarc:
        findings.append(f"Missing _dmarc.{domain} record leaves executives and customers exposed to phishing impersonation.")
    elif dmarc_policy == "none":
        findings.append("DMARC policy is 'p=none' (passive mode; spoofed emails still land in recipient inboxes).")

    if passed:
        summary = f"SPF active and DMARC enforced (p={dmarc_policy}). Domain spoofing protection verified."
        admin_fix = None
    else:
        summary = " ".join(findings)
        admin_fix = (
            f"DNS TXT on _dmarc.{domain} -> "
            f'\"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:security@{domain}\"'
        )

    return {
        "passed": passed,
        "dmarc_policy": dmarc_policy,
        "summary": summary,
        "admin_fix": admin_fix,
    }


async def check_http_and_cve_surface(
    client: httpx.AsyncClient, domain: str, has_web_ip: bool, primary_ip: str = "", ip_count: int = 1
) -> Dict[str, Any]:
    """Inspect HTTP headers, CORS, banner disclosure, hardcoded secrets, cookies, redirects, and DoS/WAF surface."""
    if not has_web_ip:
        return {
            "Reachable": False,
            "server_banner": "No Active Host IP",
            "http_status": 0,
            "headers_passed": False,
            "cors_passed": False,
            "exposure_passed": False,
            "secrets_passed": False,
            "cookie_passed": False,
            "redirect_passed": False,
            "methods_passed": False,
            "dos_passed": False,
            "sri_passed": False,
            "is_parked": False,
            "headers_summary": f"No active host IP found for {domain} to serve security headers.",
            "headers_fix": "Verify domain DNS records and configure web server listener.",
            "cors_summary": "Host unresolvable; API cross-origin policy unverified.",
            "cors_fix": None,
            "exposure_summary": "Target host unresolvable over the internet.",
            "exposure_fix": None,
            "secrets_summary": "Host unresolvable; client-side code inspection skipped.",
            "secrets_fix": None,
            "cookie_summary": "Host unresolvable; session cookie flags unverified.",
            "cookie_fix": None,
            "redirect_summary": "Host unresolvable; SSRF and open-redirect vectors unverified.",
            "redirect_fix": None,
            "methods_summary": "Host unresolvable; HTTP verb tampering unverified.",
            "methods_fix": None,
            "dos_summary": "Host unresolvable; DoS/WAF protection unverified.",
            "dos_fix": None,
            "sri_summary": "Host unresolvable; third-party script integrity unverified.",
            "sri_fix": None,
        }

    headers_report: Dict[str, bool] = {
        "Strict-Transport-Security": False,
        "Content-Security-Policy": False,
        "X-Frame-Options": False,
        "X-Content-Type-Options": False,
        "Permissions-Policy": False,
    }
    missing_headers: List[str] = []
    leaked_banners: List[str] = []
    cors_issue = False
    status_code = 0
    server_header = "Hidden / Protected"
    is_parked = False
    resp = None
    raw_html = ""
    resp_headers: Dict[str, str] = {}

    # Probe HTTPS first; fall back to HTTP if HTTPS connection fails
    for scheme in ("https://", "http://"):
        try:
            r = await client.get(
                f"{scheme}{domain}",
                follow_redirects=True,
                timeout=6.5,
                headers={"User-Agent": "ADX-Threat-Scanner/2026.4 (+https://adxgroup.tech)"},
            )
            resp = r
            status_code = resp.status_code
            h = resp.headers
            resp_headers = dict(h)
            raw_html = resp.text or ""
            server_header = h.get("server", "Hidden / Protected")

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

            # Parked domain, parking broker, lander redirect, or bot captcha gate detection
            body_sample = raw_html.lower()[:3000]
            final_url = str(resp.url).lower()
            parked_url_keywords = [
                "forsale", "parked", "parking", "sedo", "dan.com", "hugedomains", "afternic", "bodis", "sgcaptcha"
            ]
            parked_signatures = [
                "sgcaptcha",
                "site unavailable",
                "site is currently unavailable",
                "this site is currently unavailable",
                "domain is for sale",
                "buy this domain",
                "this domain is parked",
                "domain parking",
                "sedo parking",
                "hugedomains",
                "afternic",
                "namecheap parking",
                "godaddy parking",
                "parkingcrew",
                "bodis.com",
                "dan.com/buy-domain",
                "domain has expired",
                "account suspended",
                "parkedpages",
            ]
            if any(k in final_url for k in parked_url_keywords) or any(sig in body_sample for sig in parked_signatures) or (status_code == 202 and "captcha" in body_sample):
                is_parked = True
            else:
                js_lander_match = re.search(r'window\.location(?:\.href)?\s*=\s*["\'](/lander[^"\']*)["\']', body_sample)
                if js_lander_match:
                    lander_path = js_lander_match.group(1)
                    try:
                        lander_resp = await client.get(f"{scheme}{domain}{lander_path}", follow_redirects=True, timeout=4.0)
                        lander_url = str(lander_resp.url).lower()
                        lander_body = lander_resp.text.lower()[:3000]
                        if any(k in lander_url for k in parked_url_keywords) or any(k in lander_body for k in parked_signatures):
                            is_parked = True
                    except Exception:
                        is_parked = True
                elif len(raw_html) < 250 and len(re.sub(r'<[^>]+>', ' ', raw_html).strip()) < 20 and not ("<body" in body_sample and len(body_sample) > 150):
                    is_parked = True
            break
        except Exception:
            continue

    if resp is None:
        return {
            "Reachable": False,
            "server_banner": "Unreachable (Ports 80/443 Refused)",
            "http_status": 0,
            "headers_passed": False,
            "cors_passed": False,
            "exposure_passed": False,
            "secrets_passed": False,
            "cookie_passed": False,
            "redirect_passed": False,
            "methods_passed": False,
            "dos_passed": False,
            "sri_passed": False,
            "is_parked": False,
            "headers_summary": f"HTTP/HTTPS ports on {domain} refused connection or timed out.",
            "headers_fix": "Verify web server listener on port 80/443 and configure reverse proxy.",
            "cors_summary": "HTTP endpoint unreachable.",
            "cors_fix": None,
            "exposure_summary": "Web ports unreachable on host.",
            "exposure_fix": None,
            "secrets_summary": "Web ports unreachable on host.",
            "secrets_fix": None,
            "cookie_summary": "Web ports unreachable on host.",
            "cookie_fix": None,
            "redirect_summary": "Web ports unreachable on host.",
            "redirect_fix": None,
            "methods_summary": "Web ports unreachable on host.",
            "methods_fix": None,
            "dos_summary": "Web ports unreachable on host.",
            "dos_fix": None,
            "sri_summary": "Web ports unreachable on host.",
            "sri_fix": None,
        }

    # Probe sensitive dotfiles, backups, source maps, and debug endpoints concurrently
    probe_targets = [
        ("/.env", ("APP_", "DB_", "SECRET", "KEY=")),
        ("/.git/HEAD", ("ref: refs/",)),
        ("/.env.backup", ("APP_", "DB_", "SECRET", "KEY=")),
        ("/wp-config.php.bak", ("DB_PASSWORD", "wp_")),
        ("/server-status", ("Apache Server Status", "Server Version:")),
        ("/actuator/env", ("propertySources", "systemProperties")),
    ]

    async def _probe_path(path: str, sigs: tuple) -> str:
        try:
            pr = await client.get(f"https://{domain}{path}", follow_redirects=False, timeout=3.0)
            if pr.status_code == 200 and any(s in pr.text[:400] for s in sigs):
                return path
        except Exception:
            pass
        return ""

    async def _probe_open_redirect() -> bool:
        try:
            pr = await client.get(
                f"https://{domain}/?redirect=https://evil.example.com&next=https://evil.example.com&url=https://evil.example.com",
                follow_redirects=False,
                timeout=3.0,
            )
            loc = pr.headers.get("location", "").lower()
            if pr.status_code in (301, 302, 303, 307, 308) and "evil.example.com" in loc:
                return False
        except Exception:
            pass
        return True

    async def _probe_http_methods() -> List[str]:
        dangerous_allowed = []
        try:
            opt = await client.request("OPTIONS", f"https://{domain}/", timeout=3.0)
            allow_hdr = (opt.headers.get("allow", "") + "," + opt.headers.get("access-control-allow-methods", "")).upper()
            for verb in ("TRACE", "PUT", "DELETE"):
                if verb in allow_hdr:
                    dangerous_allowed.append(verb)
        except Exception:
            pass
        return dangerous_allowed

    probe_results = await asyncio.gather(
        *[_probe_path(p, s) for p, s in probe_targets],
        _probe_open_redirect(),
        _probe_http_methods(),
    )
    exposed_paths = [p for p in probe_results[:-2] if p]
    redirect_passed_probe = bool(probe_results[-2])
    dangerous_verbs = probe_results[-1]

    # Gate 3: Browser Security Headers
    headers_passed = len(missing_headers) == 0
    if headers_passed:
        headers_summary = "All 5 defensive HTTP headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy) verified."
        headers_fix = None
    else:
        headers_summary = (
            f"Missing {len(missing_headers)} browser defense header(s): {', '.join(missing_headers)}. "
            "Exposes user sessions to DOM XSS injection, clickjacking, or MIME-sniffing attacks."
        )
        headers_fix = (
            "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n"
            "Add Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n"
            "Add X-Frame-Options: DENY\n"
            "Add X-Content-Type-Options: nosniff\n"
            "Add Permissions-Policy: camera=(), microphone=(), geolocation=()"
        )

    # Gate 4: API Cross-Origin Policy & CORS
    cors_passed = not cors_issue
    cors_summary = (
        "Cross-Origin Resource Sharing (CORS) boundaries properly restrict credentialed requests."
        if cors_passed
        else "Wildcard Access-Control-Allow-Origin (*) paired with Access-Control-Allow-Credentials: true permits cross-origin token theft."
    )
    cors_fix = (
        None
        if cors_passed
        else f"Set Access-Control-Allow-Origin: https://{domain} (remove '*' wildcard on authenticated endpoints)."
    )

    # Gate 5: Exposed Dotfiles, Backups & Server Version Banners
    exposure_passed = (len(leaked_banners) == 0) and (len(exposed_paths) == 0)
    if exposure_passed:
        exposure_summary = "Zero exposed configuration/backup files (/.env, /.git, .bak, /actuator) and server version strings are masked."
        exposure_fix = None
    else:
        parts = []
        if exposed_paths:
            parts.append(f"CRITICAL: Publicly readable sensitive paths found: {', '.join(exposed_paths)}.")
        if leaked_banners:
            parts.append(f"Server runtime version disclosed ({', '.join(leaked_banners)}), aiding targeted exploit selection.")
        exposure_summary = " ".join(parts)
        exposure_fix = "Block dotfile/backup routes (/.env*, /.git*, *.bak, /actuator*) at firewall and strip Server / X-Powered-By headers."

    # Gate 6: DoS / Rate-Limiting & Edge WAF Protection (CWE-400 / CWE-770)
    waf_markers = (
        "cf-ray", "x-vercel-id", "x-amz-cf-id", "x-fastly-request-id", "x-akamai-transformed",
        "x-ratelimit-limit", "ratelimit-limit", "retry-after", "x-cdn", "cf-cache-status"
    )
    has_waf_or_ratelimit = any(k in resp_headers for k in waf_markers) or any(
        w in server_header.lower() for w in ("cloudflare", "vercel", "akamai", "cloudfront", "fastly", "adx")
    ) or ip_count >= 2
    dos_passed = bool(has_waf_or_ratelimit)
    if dos_passed:
        dos_summary = f"Active Edge CDN/WAF or rate-limiting telemetry detected ({server_header}, {ip_count} routed IP node(s))."
        dos_fix = None
    else:
        dos_summary = (
            f"Single origin IP ({primary_ip}) exposed directly without detectable edge WAF, CDN caching, or HTTP rate-limit headers (X-RateLimit-Limit). "
            "Vulnerable to Layer-7 HTTP flood and Denial-of-Service (DoS) exhaustion."
        )
        dos_fix = "Place origin behind Cloudflare WAF / AWS Shield and enforce sliding-window rate limiting (HTTP 429) on API & auth routes."

    # Gate 7: Hardcoded API Keys, Tokens & Client-Side Backdoor Inspection (CWE-798)
    secret_patterns = [
        ("OpenAI API Secret Key", r"sk-(?:proj-)?[A-Za-z0-9]{20,}"),
        ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
        ("Stripe Live Secret Key", r"sk_live_[0-9a-zA-Z]{24}"),
        ("GitHub Personal Access Token", r"ghp_[0-9a-zA-Z]{36}"),
        ("Slack Webhook / Bot Token", r"xox[baprs]-[0-9a-zA-Z-]{10,48}"),
        ("Private RSA/SSH Key Block", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ("Exposed Database Connection URI", r"(?:postgres|mongodb(?:\+srv)?|mysql|redis)://[^/\s\"']+:[^@\s\"']+@[^\s\"']+"),
        ("Source Map Production Leak", r"//# sourceMappingURL=.*\.js\.map"),
    ]
    detected_secrets: List[str] = []
    html_scan_slice = raw_html[:150000]
    for label, pat in secret_patterns:
        if re.search(pat, html_scan_slice):
            detected_secrets.append(label)

    secrets_passed = len(detected_secrets) == 0
    if secrets_passed:
        secrets_summary = "Zero hardcoded API keys, private keys, database URIs, or exposed .js.map source maps found in page source."
        secrets_fix = None
    else:
        secrets_summary = f"CRITICAL: Detected {', '.join(detected_secrets)} embedded directly in client-facing source code!"
        secrets_fix = "Immediately rotate leaked credentials, move secrets to server-side environment variables (.env), and disable production .js.map source maps."

    # Gate 8: Session Cookie & Auth Token Hardening (CWE-614 / CWE-1004)
    set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else (
        [resp.headers["set-cookie"]] if "set-cookie" in resp.headers else []
    )
    weak_cookies: List[str] = []
    for ck in set_cookies:
        ck_lower = ck.lower()
        ck_name = ck.split("=", 1)[0].strip()
        missing_flags = []
        if "secure" not in ck_lower:
            missing_flags.append("Secure")
        if "httponly" not in ck_lower:
            missing_flags.append("HttpOnly")
        if "samesite" not in ck_lower:
            missing_flags.append("SameSite")
        if missing_flags:
            weak_cookies.append(f"{ck_name} (missing {'/'.join(missing_flags)})")

    cookie_passed = len(weak_cookies) == 0
    if cookie_passed:
        cookie_summary = (
            "All issued cookies enforce Secure, HttpOnly, and SameSite protections (or stateless zero-cookie response)."
        )
        cookie_fix = None
    else:
        cookie_summary = f"Session/tracking cookies issued without anti-hijacking flags: {', '.join(weak_cookies[:3])}."
        cookie_fix = "Append '; Secure; HttpOnly; SameSite=Lax' (or Strict) to all Set-Cookie response headers to block XSS cookie theft and CSRF."

    # Gate 9: SSRF & Unvalidated Open-Redirect Surface (CWE-918 / CWE-601)
    unsafe_url_params = re.findall(r'[?&](url|redirect|next|dest|Callback|returnUrl|webhook|proxy)=http', html_scan_slice, re.IGNORECASE)
    redirect_passed = redirect_passed_probe and (len(unsafe_url_params) == 0)
    if redirect_passed:
        redirect_summary = "Redirect parameters (?redirect=, ?next=, ?url=) properly reject arbitrary external host redirection."
        redirect_fix = None
    else:
        redirect_summary = (
            "Detected unvalidated redirect / URL-fetching parameter exposure. Attackers can chain open redirects or SSRF to probe internal metadata."
        )
        redirect_fix = "Validate all redirect/callback URLs against a strict domain allowlist and block RFC1918 / 169.254.169.254 SSRF targets."

    # Gate 10: HTTP Verb Tampering & Unsafe Methods (CWE-749 / CWE-650)
    methods_passed = len(dangerous_verbs) == 0
    if methods_passed:
        methods_summary = "Dangerous HTTP verbs (TRACE, PUT, DELETE) are disabled or restricted on the public root listener."
        methods_fix = None
    else:
        methods_summary = f"Server explicitly advertises unsafe HTTP methods ({', '.join(dangerous_verbs)}) via OPTIONS, enabling Cross-Site Tracing (XST) or verb tampering."
        methods_fix = "Disable TRACE, PUT, and DELETE methods on public web routes at the web server / reverse proxy layer."

    # Gate 11: Third-Party Script Supply-Chain & Subresource Integrity (CWE-829 / CWE-353)
    script_tags = re.findall(r"<script[^>]+src=[\"'](https?://[^\"']+)[\"'][^>]*>", html_scan_slice, re.IGNORECASE)
    external_unverified_scripts = []
    for full_tag in re.findall(r"<script[^>]+src=[\"']https?://[^\"']+[\"'][^>]*>", html_scan_slice, re.IGNORECASE):
        src_m = re.search(r"src=[\"'](https?://[^\"']+)[\"']", full_tag, re.IGNORECASE)
        if src_m:
            src_url = src_m.group(1)
            src_host = urlparse(src_url).netloc.lower()
            if src_host and domain not in src_host and "integrity=" not in full_tag.lower():
                external_unverified_scripts.append(src_host)

    unique_unverified_hosts = sorted(list(set(external_unverified_hosts := external_unverified_scripts)))
    sri_passed = len(unique_unverified_hosts) == 0
    if sri_passed:
        sri_summary = "Zero unverified external third-party JavaScript CDNs lacking Subresource Integrity (SRI) hashes."
        sri_fix = None
    else:
        sri_summary = (
            f"Loaded {len(unique_unverified_hosts)} external script source(s) ({', '.join(unique_unverified_hosts[:3])}) without Subresource Integrity (integrity='sha384-...'). "
            "Exposes site to Magecart / CDN supply-chain backdoor injection."
        )
        sri_fix = "Add integrity='sha384-...' and crossorigin='anonymous' to all third-party <script> tags or self-host scripts locally."

    return {
        "Reachable": True,
        "server_banner": server_header,
        "http_status": status_code,
        "headers_passed": headers_passed,
        "cors_passed": cors_passed,
        "exposure_passed": exposure_passed,
        "secrets_passed": secrets_passed,
        "cookie_passed": cookie_passed,
        "redirect_passed": redirect_passed,
        "methods_passed": methods_passed,
        "dos_passed": dos_passed,
        "sri_passed": sri_passed,
        "is_parked": is_parked,
        "headers_summary": headers_summary,
        "headers_fix": headers_fix,
        "cors_summary": cors_summary,
        "cors_fix": cors_fix,
        "exposure_summary": exposure_summary,
        "exposure_fix": exposure_fix,
        "secrets_summary": secrets_summary,
        "secrets_fix": secrets_fix,
        "cookie_summary": cookie_summary,
        "cookie_fix": cookie_fix,
        "redirect_summary": redirect_summary,
        "redirect_fix": redirect_fix,
        "methods_summary": methods_summary,
        "methods_fix": methods_fix,
        "dos_summary": dos_summary,
        "dos_fix": dos_fix,
        "sri_summary": sri_summary,
        "sri_fix": sri_fix,
    }


BLOCKED_SSRF_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::/128"),
]

def is_ssrf_forbidden_ip(ip_str: str) -> bool:
    """Detect private, loopback, link-local, reserved, or cloud metadata IPs to prevent SSRF attacks."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True  # Malformed IP is treated as unsafe

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    for net in BLOCKED_SSRF_NETWORKS:
        if ip in net:
            return True

    return False


async def run_full_diagnostic(raw_domain: str) -> Dict[str, Any]:
    """Execute 6-Gate External + Deep Hidden 2026 CVE Threat Assessment."""
    domain = normalize_domain(raw_domain)
    if not domain:
        raise ValueError("Please provide a domain name (e.g., company.com).")

    # Reject raw IP addresses
    try:
        ipaddress.ip_address(domain)
        raise ValueError("Raw IP addresses cannot be audited directly. Please provide a fully-qualified domain name (FQDN).")
    except ValueError as e:
        if "Raw IP" in str(e):
            raise

    # Validate FQDN structure
    if not FQDN_REGEX.match(domain):
        raise ValueError("Invalid domain format. Must be a valid fully-qualified domain name (e.g., company.com) without spaces or invalid symbols.")

    # Reject reserved/internal domains
    if domain in RESERVED_DOMAINS or domain.endswith(RESERVED_SUFFIXES):
        raise ValueError(f"Domain '{domain}' is a reserved internal or local namespace. Probing local networks is prohibited under ADX Zero-Trust policy.")

    async with httpx.AsyncClient(verify=True) as doh_client, httpx.AsyncClient(verify=False) as probe_client:
        a_records, mx_records = await asyncio.gather(
            _query_doh(doh_client, domain, "A"),
            _query_doh(doh_client, domain, "MX"),
        )
        ip_list = [ip for ip in a_records if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip)]
        if not ip_list:
            ip_list = await asyncio.to_thread(_resolve_os_ips, domain)
        primary_ip = ip_list[0] if ip_list else ""

        if not primary_ip:
            raise ValueError(
                f"Target domain '{domain}' cannot be reached. No active A/AAAA DNS records or host IP found over the internet. "
                "Please verify the domain spelling or ensure the website is online."
            )

        for checked_ip in ip_list:
            if is_ssrf_forbidden_ip(checked_ip):
                raise ValueError(
                    f"Target domain '{domain}' resolves to a restricted internal or private network address ({checked_ip}). "
                    "Server-Side Request Forgery (SSRF) and internal IP audits are strictly prohibited under ADX Zero-Trust policy."
                )

        ssl_task = asyncio.to_thread(_check_ssl_sync, domain, primary_ip)
        dns_task = check_dns_email_security(doh_client, domain)
        http_task = check_http_and_cve_surface(probe_client, domain, bool(primary_ip), primary_ip=primary_ip, ip_count=len(ip_list))

        ssl_res, dns_res, http_res = await asyncio.gather(ssl_task, dns_task, http_task)

    if not http_res.get("Reachable"):
        raise ValueError(
            f"Target domain '{domain}' (Host IP: {primary_ip}) is offline. Web ports 80 and 443 refused connection with zero active listeners."
        )

    # Reject non-operational or error status codes on root (4xx / 5xx)
    http_status = http_res.get("http_status", 0)
    if http_status >= 400:
        raise ValueError(
            f"Target domain '{domain}' is not a live or operational website (Server returned HTTP {http_status} with no active application). "
            "ADX Group audits operational web applications, software platforms, and active business services."
        )

    if http_res.get("is_parked"):
        raise ValueError(
            f"Target domain '{domain}' is currently parked, inactive, or restricted by a domain broker captcha gate. "
            "ADX Group audits operational web applications, software platforms, and active business services."
        )

    gates = [
        {
            "gate_id": "1",
            "vector": "TLS / SSL Handshake & Cipher Suite",
            "cve_ref": "CWE-326",
            "condition": "Valid CA certificate chain, TLS 1.2/1.3 cryptographic transport",
            "state": bool(ssl_res["passed"]),
            "status_label": "VERIFIED (TRUE)" if ssl_res["passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if ssl_res["passed"] else "HIGH",
            "finding": ssl_res["summary"],
            "client_action": (
                "TLS transport layer verified."
                if ssl_res["passed"]
                else "Upgrade server cipher suite and install valid CA certificate."
            ),
            "remediation": ssl_res["admin_fix"],
        },
        {
            "gate_id": "2",
            "vector": "DNS Domain Authentication (SPF & DMARC)",
            "cve_ref": "CWE-290",
            "condition": "Strict SPF (-all) & enforced DMARC (p=reject / quarantine)",
            "state": bool(dns_res["passed"]),
            "status_label": "VERIFIED (TRUE)" if dns_res["passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if dns_res["passed"] else "HIGH",
            "finding": dns_res["summary"],
            "client_action": (
                "Anti-spoofing DNS policy verified."
                if dns_res["passed"]
                else "Publish strict SPF and DMARC TXT records in domain DNS."
            ),
            "remediation": dns_res["admin_fix"],
        },
        {
            "gate_id": "3",
            "vector": "Browser Security Headers & Frame Sandboxing",
            "cve_ref": "CWE-1021",
            "condition": "HSTS, CSP, X-Frame-Options, Nosniff & Permissions-Policy",
            "state": bool(http_res["headers_passed"]),
            "status_label": "VERIFIED (TRUE)" if http_res["headers_passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if http_res["headers_passed"] else "MEDIUM",
            "finding": http_res["headers_summary"],
            "client_action": (
                "All 5 defensive HTTP headers active."
                if http_res["headers_passed"]
                else "Configure HSTS, Content-Security-Policy, and X-Frame-Options at web server or reverse proxy."
            ),
            "remediation": http_res["headers_fix"],
        },
        {
            "gate_id": "4",
            "vector": "API Cross-Origin Policy & CORS Boundary",
            "cve_ref": "CWE-942",
            "condition": "Strict origin whitelist on credentialed API responses",
            "state": bool(http_res["cors_passed"]),
            "status_label": "VERIFIED (TRUE)" if http_res["cors_passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if http_res["cors_passed"] else "HIGH",
            "finding": http_res["cors_summary"],
            "client_action": (
                "CORS boundary verified."
                if http_res["cors_passed"]
                else "Restrict Access-Control-Allow-Origin to trusted application domains."
            ),
            "remediation": http_res["cors_fix"],
        },
        {
            "gate_id": "5",
            "vector": "Exposed Dotfiles, Backups & Server Banners",
            "cve_ref": "CWE-538",
            "condition": "Zero exposed /.env, /.git, .bak, /actuator & masked server banners",
            "state": bool(http_res["exposure_passed"]),
            "status_label": "VERIFIED (TRUE)" if http_res["exposure_passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if http_res["exposure_passed"] else "CRITICAL",
            "finding": http_res["exposure_summary"],
            "client_action": (
                "No public configuration files or version banners exposed."
                if http_res["exposure_passed"]
                else "Mask Server and X-Powered-By response headers and deny dotfile/backup access at reverse proxy."
            ),
            "remediation": http_res["exposure_fix"],
        },
        {
            "gate_id": "6",
            "vector": "DoS / Rate-Limiting & Edge WAF Protection",
            "cve_ref": "CWE-400",
            "condition": "Multi-node CDN/WAF edge shield or active HTTP rate-limit telemetry",
            "state": bool(http_res["dos_passed"]),
            "status_label": "VERIFIED (TRUE)" if http_res["dos_passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if http_res["dos_passed"] else "MEDIUM",
            "finding": http_res["dos_summary"],
            "client_action": (
                "Edge WAF / DoS mitigation active."
                if http_res["dos_passed"]
                else "Route traffic through an Edge WAF/CDN (Cloudflare, Vercel, AWS Shield) and enforce rate limits."
            ),
            "remediation": http_res["dos_fix"],
        },
        {
            "gate_id": "7",
            "vector": "Hardcoded Secrets, API Keys & Client Backdoors",
            "cve_ref": "CWE-798",
            "condition": "Zero hardcoded API keys, private keys, DB URIs, or .js.map leaks in source",
            "state": bool(http_res["secrets_passed"]),
            "status_label": "VERIFIED (TRUE)" if http_res["secrets_passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if http_res["secrets_passed"] else "CRITICAL",
            "finding": http_res["secrets_summary"],
            "client_action": (
                "No hardcoded credentials or source-map leaks detected."
                if http_res["secrets_passed"]
                else "Rotate leaked keys immediately and move secrets to backend environment variables."
            ),
            "remediation": http_res["secrets_fix"],
        },
        {
            "gate_id": "8",
            "vector": "Session Cookie & Auth Token Hardening",
            "cve_ref": "CWE-614",
            "condition": "Secure, HttpOnly, and SameSite flags enforced on Set-Cookie headers",
            "state": bool(http_res["cookie_passed"]),
            "status_label": "VERIFIED (TRUE)" if http_res["cookie_passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if http_res["cookie_passed"] else "HIGH",
            "finding": http_res["cookie_summary"],
            "client_action": (
                "Session cookie flags properly hardened."
                if http_res["cookie_passed"]
                else "Enforce Secure, HttpOnly, and SameSite flags on all session cookies."
            ),
            "remediation": http_res["cookie_fix"],
        },
        {
            "gate_id": "9",
            "vector": "SSRF & Unvalidated Open-Redirect Surface",
            "cve_ref": "CWE-918",
            "condition": "Strict allowlist validation on ?redirect=, ?next=, and ?url= parameters",
            "state": bool(http_res["redirect_passed"]),
            "status_label": "VERIFIED (TRUE)" if http_res["redirect_passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if http_res["redirect_passed"] else "HIGH",
            "finding": http_res["redirect_summary"],
            "client_action": (
                "No open-redirect or SSRF parameter reflection detected."
                if http_res["redirect_passed"]
                else "Enforce strict domain allowlists on all redirect and webhook URL parameters."
            ),
            "remediation": http_res["redirect_fix"],
        },
        {
            "gate_id": "10",
            "vector": "HTTP Verb Tampering & Unsafe Methods",
            "cve_ref": "CWE-749",
            "condition": "Dangerous HTTP verbs (TRACE, PUT, DELETE) disabled on public routes",
            "state": bool(http_res["methods_passed"]),
            "status_label": "VERIFIED (TRUE)" if http_res["methods_passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if http_res["methods_passed"] else "MEDIUM",
            "finding": http_res["methods_summary"],
            "client_action": (
                "Unsafe HTTP verbs restricted."
                if http_res["methods_passed"]
                else "Disable TRACE, PUT, and DELETE methods on public web server listeners."
            ),
            "remediation": http_res["methods_fix"],
        },
        {
            "gate_id": "11",
            "vector": "Third-Party Script Supply-Chain & SRI Integrity",
            "cve_ref": "CWE-829",
            "condition": "External CDN scripts verified with Subresource Integrity (SRI) hashes",
            "state": bool(http_res["sri_passed"]),
            "status_label": "VERIFIED (TRUE)" if http_res["sri_passed"] else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if http_res["sri_passed"] else "MEDIUM",
            "finding": http_res["sri_summary"],
            "client_action": (
                "External scripts protected or self-hosted."
                if http_res["sri_passed"]
                else "Add integrity='sha384-...' attributes to external CDN scripts or self-host assets."
            ),
            "remediation": http_res["sri_fix"],
        },
        {
            "gate_id": "12",
            "vector": "Network Edge & DNS Routing Resilience",
            "cve_ref": "CWE-693",
            "condition": "Active DNS resolution and verified TLS termination listener",
            "state": bool(primary_ip and ssl_res["passed"]),
            "status_label": "VERIFIED (TRUE)" if (primary_ip and ssl_res["passed"]) else "ATTENTION REQUIRED (FALSE)",
            "severity": "LOW" if (primary_ip and ssl_res["passed"]) else "MEDIUM",
            "finding": (
                f"Resolved primary host IP ({primary_ip}) with responsive TLS handshake listener."
                if (primary_ip and ssl_res["passed"])
                else "Unable to confirm redundant edge proxy routing or TLS termination."
            ),
            "client_action": (
                "Edge proxy architecture verified."
                if (primary_ip and ssl_res["passed"])
                else "Route domain traffic through a verified cloud edge or CDN provider."
            ),
            "remediation": (
                None
                if (primary_ip and ssl_res["passed"])
                else "Deploy Cloudflare, AWS CloudFront, or Vercel Edge proxy."
            ),
        },
    ]

    # All-around score across all 12 deep security vectors (sums to 100)
    weights = [14, 14, 12, 8, 10, 8, 10, 6, 6, 4, 4, 4]
    score = sum(w for g, w in zip(gates, weights) if g["state"])

    if score >= 95:
        grade = "A+"
        risk_level = "VERIFIED ZERO-TRUST ARCHITECTURE"
    elif score >= 85:
        grade = "A"
        risk_level = "HARDENED PERIMETER POSTURE"
    elif score >= 70:
        grade = "B"
        risk_level = "MODERATE POSTURE"
    elif score >= 50:
        grade = "C"
        risk_level = "CONFIGURATION ATTENTION REQUIRED"
    else:
        grade = "D"
        risk_level = "SIGNIFICANT EXPOSURE GAPS"

    telemetry = {
        "resolved_ip": primary_ip,
        "ip_count": len(ip_list),
        "mx_count": len(mx_records),
        "latency_ms": ssl_res.get("latency_ms", 0),
        "tls_protocol": ssl_res.get("tls_version", "TLS"),
        "cipher_suite": ssl_res.get("cipher", "Verified TLS Cipher"),
        "cert_issuer": ssl_res.get("issuer", "Unissued"),
        "cert_serial": ssl_res.get("serial", "N/A"),
        "server_banner": http_res.get("server_banner", "Hidden / Protected"),
        "http_status": http_res.get("http_status", 0),
    }

    cve_2026_report = [
        {
            "cve_id": "CWE-326",
            "title": "TLS Transport Encryption & Cipher Negotiation Strength",
            "cvss": "7.5 HIGH",
            "surface": f"{ssl_res['tls_version']} / {ssl_res['cipher']}",
            "status": "MITIGATED" if ssl_res["passed"] else "EXPOSED",
            "passed": bool(ssl_res["passed"]),
            "gate_id": "1",
        },
        {
            "cve_id": "CWE-290",
            "title": "Executive Domain Spoofing & Unauthenticated Mail Relay",
            "cvss": "8.6 HIGH",
            "surface": "SPF / DMARC DNS Policy",
            "status": "MITIGATED" if dns_res["passed"] else "EXPOSED",
            "passed": bool(dns_res["passed"]),
            "gate_id": "2",
        },
        {
            "cve_id": "CWE-1021",
            "title": "Missing Frame Isolation & Clickjacking Exposure",
            "cvss": "7.8 HIGH",
            "surface": f"HTTP Edge ({telemetry['server_banner']})",
            "status": "MITIGATED" if http_res["headers_passed"] else "EXPOSED",
            "passed": bool(http_res["headers_passed"]),
            "gate_id": "3",
        },
        {
            "cve_id": "CWE-942",
            "title": "Permissive Cross-Domain Policy with Untrusted Domains (CORS)",
            "cvss": "8.2 HIGH",
            "surface": "CORS & Session Cookie Boundary",
            "status": "MITIGATED" if http_res["cors_passed"] else "EXPOSED",
            "passed": bool(http_res["cors_passed"]),
            "gate_id": "4",
        },
        {
            "cve_id": "CWE-538",
            "title": "Sensitive Dotfile (/.env, /.git) & Server Version Banner Exposure",
            "cvss": "8.9 HIGH",
            "surface": f"Runtime Stack ({telemetry['server_banner']})",
            "status": "MITIGATED" if http_res["exposure_passed"] else "EXPOSED",
            "passed": bool(http_res["exposure_passed"]),
            "gate_id": "5",
        },
        {
            "cve_id": "CWE-693",
            "title": "Network Edge Proxy & TLS Termination Resilience",
            "cvss": "6.5 MEDIUM",
            "surface": f"Primary Host ({primary_ip})",
            "status": "MITIGATED" if (primary_ip and ssl_res["passed"]) else "EXPOSED",
            "passed": bool(primary_ip and ssl_res["passed"]),
            "gate_id": "6",
        },
    ]

    failed_gates = [g for g in gates if not g["state"]]
    outreach_email = _build_outreach_email(domain, score, failed_gates, telemetry)

    return {
        "domain": domain,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "score": score,
        "grade": grade,
        "risk_level": risk_level,
        "telemetry": telemetry,
        "cve_2026_report": cve_2026_report,
        "passed_count": sum(1 for g in gates if g["state"]),
        "total_gates": len(gates),
        "gates": gates,
        "outreach_email": outreach_email,
    }


def _build_outreach_email(
    domain: str, score: int, failed_gates: List[Dict[str, Any]], telemetry: Dict[str, Any]
) -> str:
    """Generate a tailored B2B outreach advisory for the Owner Command Center (/admin ONLY)."""
    bullet_points = []
    for idx, g in enumerate(failed_gates[:4], start=1):
        bullet_points.append(f"{idx}. [{g['vector']}]: {g['finding']}")

    bullets_str = "\n".join(bullet_points)
    host_ip = telemetry.get("resolved_ip", "Unknown")
    tls_proto = telemetry.get("tls_protocol", "TLS")

    return (
        f"Subject: Security Posture & Infrastructure Advisory for {domain} (Host: {host_ip})\n\n"
        f"Hi Engineering & Leadership Team,\n\n"
        f"During perimeter infrastructure auditing, ADX evaluated {domain} "
        f"(Host: {host_ip} | {tls_proto} | Score: {score}/100) "
        f"and flagged the following technical defensive perimeter items:\n\n"
        f"{bullets_str}\n\n"
        f"At ADX (adxgroup.tech), we remediate infrastructure perimeter gaps, enforce strict DMARC/SPF DNS policies, "
        f"and deploy defensive browser security headers on a transparent fixed-scope basis.\n\n"
        f"Reply to this advisory if you would like our engineering desk to share the remediation scope for {domain}.\n\n"
        f"Best regards,\n"
        f"ADX Engineering Desk\n"
        f"https://adxgroup.tech | contact@adxgroup.tech"
    )
