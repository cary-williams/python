#!/usr/bin/env python3
"""
prism.py
also available as web app: https://github.com/cary-williams/risk-shield
Purpose:
This script performs a lightweight, non-invasive vendor security and compliance
triage prior to initiating a full risk assessment. It gathers publicly observable
signals to help quickly assess vendor maturity, identify obvious gaps, and determine
whether deeper due diligence or evidence collection is warranted.

Results are informational only and are not a substitute for formal audits or validated
compliance artifacts.

Vendor Risk Snapshot includes:
- Framework claims (SOC, PCI DSS, GDPR, ISO 27001, CCPA)
- Trust portal signals
- DNSSEC status (DNSKEY + DS)
- SPF presence with summary and lightweight correctness checks
- DMARC presence, policy, pct, and rua/ruf indicators
- TLS posture checks:
  - Negotiated TLS version
  - TLS 1.2 or higher enforcement
  - TLS 1.1 and TLS 1.0 allowance detection
  - Certificate validity and days until expiry
  - HSTS header presence and configuration
- security.txt discovery and parsing
- robots.txt and sitemap discovery
- Sitemap-based page discovery with filtering to exclude likely blog content
- Status page detection

Install (inside a virtual environment):
  pip install requests beautifulsoup4 tldextract dnspython

Usage:
  python prism.py --domain example.com

  python prism.py --domain example.com --debug
    Enables additional diagnostic output for troubleshooting and validation.
    Debug mode displays all scanned pages regardless of HTTP status and exposes
    internal discovery details such as sitemap-derived URLs and filtered exclusions.
    This mode is intended for development and tuning, not routine triage runs.

  python prism.py --domain example.com --json out.json
    Outputs results to the console as usual and also writes the full snapshot
    to a JSON file for later review or automation.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import warnings
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
import tldextract
from bs4 import BeautifulSoup


# ----------------------------
# Configuration
# ----------------------------

DEFAULT_PATH_CANDIDATES = [
    "/",
    "/trust",
    "/trust-center",
    "/trustcenter",
    "/security",
    "/security-center",
    "/security-and-compliance",
    "/compliance",
    "/legal/security",
    "/legal",
    "/privacy",
    "/about/security",
    "/company/security",
    "/resources/security",
]

COMMON_SUBDOMAINS = ["trust", "security", "compliance", "status"]

DEFAULT_HEADERS = {
    "User-Agent": "VendorRiskSnapshot/1.9 (+security-review; contact: you@example.com)"
}

SOC_KEYWORDS = [
    r"\bsoc\s*1\b",
    r"\bsoc\s*2\b",
    r"\bsoc\s*3\b",
    r"\bsoc1\b",
    r"\bsoc2\b",
    r"\bsoc3\b",
    r"\bservice organization control\b",
    r"\btype\s*i\b",
    r"\btype\s*ii\b",
]

REQUEST_GATED_PATTERNS = [
    r"\bupon request\b",
    r"\brequest (a|the) report\b",
    r"\brequest access\b",
    r"\bnda\b",
    r"\bsign (an|the) nda\b",
    r"\bavailable (to|for) customers\b",
    r"\bcustomer portal\b",
    r"\btrust portal\b",
    r"\bcontact (us|sales)\b",
]

LOGIN_GATED_PATTERNS = [
    r"\blog ?in\b",
    r"\bsign ?in\b",
    r"\bplease authenticate\b",
    r"\baccount required\b",
    r"\bcreate an account\b",
    r"\baccess denied\b",
]

TRUST_PORTAL_SIGNALS = [
    r"\bvanta\b",
    r"\bdrata\b",
    r"\bsecureframe\b",
    r"\bsafebase\b",
    r"\bhyperproof\b",
    r"\btrustcloud\b",
]

FRAMEWORK_PATTERNS: Dict[str, List[str]] = {
    "PCI DSS": [
        r"\bpci\s*dss\b",
        r"\bpci-dss\b",
        r"\bpayment card industry\b.*\bdata security standard\b",
        r"\bpci\b",
    ],
    "GDPR": [r"\bgdpr\b", r"\bgeneral data protection regulation\b"],
    "ISO 27001": [
        r"\biso\s*/\s*iec\s*27001\b",
        r"\biso/iec\s*27001\b",
        r"\biso\s*27001\b",
        r"\b27001\b",
    ],
    "CCPA": [r"\bccpa\b", r"\bcalifornia consumer privacy act\b"],
}

PCI_CONTEXT_REQUIRED = re.compile(
    r"\b(dss|level\s*\d|merchant|service provider|attest|aoc|roc|compliance)\b",
    re.IGNORECASE,
)
PCI_NEGATIVES = [r"\bpci express\b"]
ISO_GATE_PATTERNS = [
    re.compile(r"\biso\b", re.IGNORECASE),
    re.compile(r"\biso\s*/\s*iec\b", re.IGNORECASE),
    re.compile(r"\bcertif", re.IGNORECASE),
]

# Patterns used to identify likely blog content to exclude from sitemap-derived checks.
BLOG_EXCLUDE_PATTERNS = [
    r"/blog/",
    r"/posts/",
    r"/news/",
    r"/article/",
    r"/archives/",
    r"/category/",
    r"/tag/",
    r"/tags/",
    r"/feed",
    r"/author/",
    r"/202[0-9]/",  # date-based paths like /2024/05/...
]


# ----------------------------
# Data model
# ----------------------------

@dataclass
class PageScanResult:
    url: str
    status_code: Optional[int]
    fetched: bool
    reason: Optional[str]
    title: Optional[str]
    soc_hits: List[str]
    request_gated_hits: List[str]
    login_gated_hits: List[str]
    trust_portal_hits: List[str]
    frameworks_found: Dict[str, List[str]]
    extracted_sample: Optional[str]


@dataclass
class SocAssessment:
    soc_claimed: bool
    access: str
    evidence: str
    confidence: float
    notes: List[str]
    supporting_urls: List[str]


@dataclass
class FrameworkAssessment:
    framework: str
    claimed: bool
    confidence: float
    evidence: str
    notes: List[str]
    supporting_urls: List[str]


@dataclass
class SpfAssessment:
    present: bool
    record: Optional[str]
    summary: Optional[str]
    policy: Optional[str]
    dns_lookup_estimate: Optional[int]
    lookup_risk: Optional[bool]
    length: Optional[int]
    warnings: List[str]


@dataclass
class DmarcAssessment:
    present: bool
    policy: Optional[str]
    pct: Optional[int]
    rua_present: Optional[bool]
    ruf_present: Optional[bool]
    warnings: List[str]


@dataclass
class HstsAssessment:
    present: bool
    raw: Optional[str]
    max_age: Optional[int]
    include_subdomains: Optional[bool]
    preload: Optional[bool]


@dataclass
class SecurityTxtAssessment:
    present: bool
    url: Optional[str]
    contact: List[str]
    expires: Optional[str]
    policy: List[str]
    encryption: List[str]
    acknowledgments: List[str]
    preferred_languages: Optional[str]
    warnings: List[str]


@dataclass
class RobotsAssessment:
    present: bool
    url: Optional[str]
    sitemaps: List[str]


@dataclass
class StatusPageAssessment:
    present: bool
    url: Optional[str]
    status_code: Optional[int]
    title: Optional[str]
    notes: List[str]


@dataclass
class DnsTlsAssessment:
    dnssec_status: str  # "enabled" | "partial" | "not_enabled" | "unknown"
    spf: SpfAssessment
    dmarc: DmarcAssessment
    tls_version: Optional[str]
    tls_ok_1_2_plus: Optional[bool]
    tls_1_1_allowed: Optional[bool]
    tls_1_0_allowed: Optional[bool]
    tls_cert_valid: Optional[bool]
    tls_cert_not_before: Optional[str]
    tls_cert_not_after: Optional[str]
    tls_cert_days_until_expiry: Optional[int]
    hsts: HstsAssessment
    security_txt: SecurityTxtAssessment
    robots: RobotsAssessment
    status_page: StatusPageAssessment


@dataclass
class VendorSnapshot:
    vendor_domain: str
    base_url: str
    scanned_at_utc: str
    pages_scanned: int
    pages: List[PageScanResult]
    soc: SocAssessment
    frameworks: Dict[str, FrameworkAssessment]
    dns_tls: DnsTlsAssessment


# ----------------------------
# Helpers
# ----------------------------

def normalize_domain(domain: str) -> str:
    domain = domain.strip().replace("http://", "").replace("https://", "")
    return domain.split("/")[0].lower()


def build_base_url(domain: str) -> str:
    return f"https://{domain}"


def clean_url(u: str) -> str:
    if u.startswith("https://"):
        return u.replace(":443/", "/")
    if u.startswith("http://"):
        return u.replace(":80/", "/")
    return u


def get_registrable_domain(domain: str) -> str:
    ext = tldextract.extract(domain)
    return ext.top_domain_under_public_suffix or domain


def compile_patterns(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


SOC_PATTERNS = compile_patterns(SOC_KEYWORDS)
REQUEST_PATTERNS = compile_patterns(REQUEST_GATED_PATTERNS)
LOGIN_PATTERNS = compile_patterns(LOGIN_GATED_PATTERNS)
PORTAL_PATTERNS = compile_patterns(TRUST_PORTAL_SIGNALS)
FRAMEWORK_COMPILED: Dict[str, List[re.Pattern]] = {n: compile_patterns(p) for n, p in FRAMEWORK_PATTERNS.items()}
PCI_NEG_PATTERNS = compile_patterns(PCI_NEGATIVES)
BLOG_EXCLUDE_COMPILED = [re.compile(p, re.IGNORECASE) for p in BLOG_EXCLUDE_PATTERNS]


def fetch_url(url: str, timeout: int) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        return r, None
    except requests.RequestException as e:
        return None, str(e)


def extract_visible_text(html: str) -> Tuple[Optional[str], str]:
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else None
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(separator=" ")).strip()
    return title, text


def find_hits(patterns: List[re.Pattern], text: str) -> List[str]:
    return [p.pattern for p in patterns if p.search(text)]


def has_nearby(text: str, a_patterns: List[re.Pattern], b_patterns: List[re.Pattern], window: int = 220) -> bool:
    spans: List[Tuple[int, int]] = []
    for ap in a_patterns:
        for m in ap.finditer(text):
            spans.append((m.start(), m.end()))
    if not spans:
        return False
    for start, end in spans:
        chunk = text[max(0, start - window) : min(len(text), end + window)]
        if any(bp.search(chunk) for bp in b_patterns):
            return True
    return False


def generate_candidate_urls(base_url: str, domain: str) -> List[str]:
    out: List[str] = [urljoin(base_url, p) for p in DEFAULT_PATH_CANDIDATES]
    reg = get_registrable_domain(domain)
    out.extend([f"https://{s}.{reg}/" for s in COMMON_SUBDOMAINS])
    seen = set()
    uniq: List[str] = []
    for u in out:
        if u not in seen:
            uniq.append(u)
            seen.add(u)
    return uniq


def is_same_registrable_domain(url: str, vendor_domain: str) -> bool:
    host = urlparse(url).hostname or ""
    return get_registrable_domain(host) == get_registrable_domain(vendor_domain)


def discover_links_from_homepage(homepage_html: str, homepage_url: str, vendor_domain: str) -> List[str]:
    soup = BeautifulSoup(homepage_html, "html.parser")
    keywords = ["trust", "security", "compliance", "soc", "audit", "privacy", "legal", "iso", "pci", "gdpr"]
    found: List[str] = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        text = (a.get_text() or "").strip().lower()
        hay = f"{href} {text}".lower()
        if any(k in hay for k in keywords):
            abs_u = urljoin(homepage_url, href)
            if is_same_registrable_domain(abs_u, vendor_domain):
                found.append(abs_u)
    seen = set()
    uniq: List[str] = []
    for u in found:
        if u not in seen:
            uniq.append(u)
            seen.add(u)
    return uniq


def detect_frameworks(text: str) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    for name, patterns in FRAMEWORK_COMPILED.items():
        hits = find_hits(patterns, text)
        if not hits:
            continue

        if name == "PCI DSS":
            pci_only = all(h == r"\bpci\b" for h in hits)
            if pci_only:
                if any(neg.search(text) for neg in PCI_NEG_PATTERNS):
                    continue
                if not PCI_CONTEXT_REQUIRED.search(text):
                    continue

        if name == "ISO 27001":
            matched_broad = any(h == r"\b27001\b" for h in hits)
            matched_specific = any(h != r"\b27001\b" for h in hits)
            if matched_broad and not matched_specific:
                if not any(g.search(text) for g in ISO_GATE_PATTERNS):
                    continue

        found[name] = hits
    return found


# ----------------------------
# DNSSEC / SPF / DMARC / TLS / HSTS
# ----------------------------

def dns_resolve_exists(qname: str, rtype: str, lifetime: int = 6) -> bool:
    try:
        ans = dns.resolver.resolve(qname, rtype, lifetime=lifetime)
        return len(ans) > 0
    except Exception:
        return False


def check_dnssec_status(domain: str) -> str:
    try:
        has_dnskey = dns_resolve_exists(domain, "DNSKEY")
        has_ds = dns_resolve_exists(domain, "DS")
        if has_dnskey and has_ds:
            return "enabled"
        if has_dnskey and not has_ds:
            return "partial"
        if (not has_dnskey) and (not has_ds):
            return "not_enabled"
        return "partial" if has_dnskey or has_ds else "unknown"
    except Exception:
        return "unknown"


def check_spf(domain: str) -> Tuple[bool, Optional[str]]:
    try:
        ans = dns.resolver.resolve(domain, "TXT", lifetime=6)
        for r in ans:
            txt = r.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                return True, txt
        return False, None
    except Exception:
        return False, None


def parse_spf_policy(spf_record: str) -> Optional[str]:
    rec = spf_record.strip()
    m = re.search(r"\s([~?\-\+]?all)\s*$", rec, re.IGNORECASE) or re.search(r"([~?\-\+]?all)$", rec, re.IGNORECASE)
    return m.group(1).lower() if m else None


def spf_dns_lookup_estimate(spf_record: str) -> int:
    rec = spf_record.lower()
    include_n = len(re.findall(r"\binclude:", rec))
    redirect_n = len(re.findall(r"\bredirect=", rec))
    exists_n = len(re.findall(r"\bexists:", rec))
    a_n = len(re.findall(r"(?<![a-z0-9])a(?::|\b)", rec))
    mx_n = len(re.findall(r"(?<![a-z0-9])mx(?::|\b)", rec))
    ptr_n = len(re.findall(r"(?<![a-z0-9])ptr(?::|\b)", rec))
    return include_n + redirect_n + exists_n + a_n + mx_n + ptr_n


def summarize_spf(spf_record: str) -> str:
    policy = parse_spf_policy(spf_record)
    includes = len(re.findall(r"\binclude:", spf_record, re.IGNORECASE))
    has_ip4 = bool(re.search(r"\bip4:", spf_record, re.IGNORECASE))
    has_ip6 = bool(re.search(r"\bip6:", spf_record, re.IGNORECASE))
    lookups = spf_dns_lookup_estimate(spf_record)
    return f"policy={policy}, includes={includes}, lookups_est={lookups}, has_ip4={has_ip4}, has_ip6={has_ip6}, length={len(spf_record.strip())}"


def assess_spf(spf_present: bool, spf_record: Optional[str]) -> SpfAssessment:
    warnings_list: List[str] = []
    if not spf_present or not spf_record:
        return SpfAssessment(False, None, None, None, None, None, None, [])

    rec = spf_record.strip()
    policy = parse_spf_policy(rec)
    lookups = spf_dns_lookup_estimate(rec)
    length = len(rec)

    lookup_risk = lookups > 10
    if lookup_risk:
        warnings_list.append(f"SPF may exceed DNS lookup limit (estimated {lookups} > 10).")

    if policy in ("+all", "all"):
        warnings_list.append("SPF policy appears permissive (+all).")
    if policy is None:
        warnings_list.append("SPF policy does not clearly end with an all mechanism (-all, ~all, ?all, +all).")
    if length > 255:
        warnings_list.append("SPF record length > 255 characters. Some DNS setups may split TXT strings and break parsing.")
    if length > 512:
        warnings_list.append("SPF record length is very large (>512). Delivery issues are more likely.")

    return SpfAssessment(
        present=True,
        record=rec,
        summary=summarize_spf(rec),
        policy=policy,
        dns_lookup_estimate=lookups,
        lookup_risk=lookup_risk,
        length=length,
        warnings=warnings_list,
    )


def check_dmarc(domain: str) -> Tuple[bool, Optional[str], Optional[str]]:
    try:
        ans = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=6)
        raw = " ".join(a.to_text().strip('"') for a in ans)
        m = re.search(r"p=(reject|quarantine|none)", raw, re.IGNORECASE)
        policy = m.group(1).lower() if m else None
        return True, policy, raw
    except Exception:
        return False, None, None


def parse_dmarc_tags(raw: str) -> Tuple[Optional[int], bool, bool]:
    pct = None
    m_pct = re.search(r"\bpct\s*=\s*(\d{1,3})\b", raw, re.IGNORECASE)
    if m_pct:
        try:
            pct = int(m_pct.group(1))
        except Exception:
            pct = None
    rua_present = bool(re.search(r"\brua\s*=\s*[^;]+", raw, re.IGNORECASE))
    ruf_present = bool(re.search(r"\bruf\s*=\s*[^;]+", raw, re.IGNORECASE))
    return pct, rua_present, ruf_present


def assess_dmarc(present: bool, policy: Optional[str], raw: Optional[str]) -> DmarcAssessment:
    warnings_list: List[str] = []
    if not present or not raw:
        return DmarcAssessment(False, None, None, None, None, [])

    pct, rua_present, ruf_present = parse_dmarc_tags(raw)

    if policy == "none":
        warnings_list.append("DMARC policy is none (monitor only).")
    if policy in (None, ""):
        warnings_list.append("DMARC record present but policy tag p= not found.")
    if pct is not None and pct < 100:
        warnings_list.append(f"DMARC pct is {pct}, policy not applied to all mail.")
    if not rua_present:
        warnings_list.append("DMARC rua reporting address not found.")

    return DmarcAssessment(True, policy, pct, rua_present, ruf_present, warnings_list)


def tls_handshake(domain: str, context: ssl.SSLContext, timeout: int = 8) -> Tuple[Optional[str], Optional[dict], Optional[str]]:
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.version(), ssock.getpeercert(), None
    except Exception as e:
        return None, None, str(e)


def probe_legacy_tls_allowed(domain: str, protocol_attr: str, timeout: int = 8) -> Optional[bool]:
    proto = getattr(ssl, protocol_attr, None)
    if proto is None:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = ssl.SSLContext(proto)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_default_certs()
        v, _, err = tls_handshake(domain, ctx, timeout=timeout)
        return err is None and v is not None
    except Exception:
        return None


def parse_cert_time_utc(timestr: str) -> Optional[datetime]:
    try:
        fmt = "%b %d %H:%M:%S %Y %Z"
        return datetime.strptime(timestr, fmt).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def check_tls(domain: str, timeout: int = 8) -> Tuple[
    Optional[str],
    Optional[bool],
    Optional[bool],
    Optional[str],
    Optional[str],
    Optional[int],
    Optional[bool],
    Optional[bool],
]:
    modern = ssl.create_default_context()
    modern.set_ciphers("DEFAULT:@SECLEVEL=2")

    negotiated, cert, err = tls_handshake(domain, modern, timeout=timeout)
    if err or not negotiated:
        return None, None, None, None, None, None, None, None

    not_before = cert.get("notBefore") if cert else None
    not_after = cert.get("notAfter") if cert else None

    cert_valid = None
    days_until_expiry = None
    if not_before and not_after:
        nb = parse_cert_time_utc(not_before)
        na = parse_cert_time_utc(not_after)
        now = datetime.now(timezone.utc)
        if nb and na:
            cert_valid = nb <= now <= na
            days_until_expiry = int((na - now).total_seconds() // 86400)

    tls_ok = bool("1.2" in negotiated or "1.3" in negotiated)

    tls11_allowed = probe_legacy_tls_allowed(domain, "PROTOCOL_TLSv1_1", timeout=timeout)
    tls10_allowed = probe_legacy_tls_allowed(domain, "PROTOCOL_TLSv1", timeout=timeout)

    return negotiated, tls_ok, cert_valid, not_before, not_after, days_until_expiry, tls11_allowed, tls10_allowed


def parse_hsts(header_value: str) -> Tuple[Optional[int], Optional[bool], Optional[bool]]:
    max_age = None
    hv = header_value.strip()
    m = re.search(r"max-age\s*=\s*(\d+)", hv, re.IGNORECASE)
    if m:
        try:
            max_age = int(m.group(1))
        except Exception:
            max_age = None
    include_subdomains = bool(re.search(r"\bincludesubdomains\b", hv, re.IGNORECASE))
    preload = bool(re.search(r"\bpreload\b", hv, re.IGNORECASE))
    return max_age, include_subdomains, preload


def check_hsts(base_url: str, timeout: int = 10) -> HstsAssessment:
    try:
        r = requests.get(base_url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        h = r.headers.get("Strict-Transport-Security")
        if not h:
            return HstsAssessment(False, None, None, None, None)
        max_age, inc, pre = parse_hsts(h)
        return HstsAssessment(True, h, max_age, inc, pre)
    except Exception:
        return HstsAssessment(False, None, None, None, None)


# ----------------------------
# security.txt, robots/sitemap, status page, sitemap parsing with blog exclusion
# ----------------------------

def fetch_text(url: str, timeout: int) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    resp, err = fetch_url(url, timeout=timeout)
    if resp is None:
        return None, None, err
    return resp.text or "", resp.status_code, None


def parse_security_txt(body: str) -> Dict[str, List[str]]:
    fields: Dict[str, List[str]] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        fields.setdefault(k, []).append(v)
    return fields


def check_security_txt(base_url: str, timeout: int = 10) -> SecurityTxtAssessment:
    candidates = [
        urljoin(base_url.rstrip("/") + "/", ".well-known/security.txt"),
        urljoin(base_url.rstrip("/") + "/", "security.txt"),
    ]
    warnings_list: List[str] = []
    for u in candidates:
        body, status, err = fetch_text(u, timeout=timeout)
        if err:
            continue
        if status and 200 <= status < 300 and body is not None:
            fields = parse_security_txt(body)
            contact = fields.get("contact", [])
            expires_list = fields.get("expires", [])
            expires = expires_list[0] if expires_list else None
            policy = fields.get("policy", [])
            encryption = fields.get("encryption", [])
            acknowledgments = fields.get("acknowledgments", [])
            preferred_languages_list = fields.get("preferred-languages", [])
            preferred_languages = preferred_languages_list[0] if preferred_languages_list else None

            if not contact:
                warnings_list.append("security.txt present but Contact field not found.")
            if expires is None:
                warnings_list.append("security.txt present but Expires field not found.")
            else:
                if not re.search(r"\d{4}", expires):
                    warnings_list.append("security.txt Expires field does not look like a valid date.")

            return SecurityTxtAssessment(
                present=True,
                url=u,
                contact=contact,
                expires=expires,
                policy=policy,
                encryption=encryption,
                acknowledgments=acknowledgments,
                preferred_languages=preferred_languages,
                warnings=warnings_list,
            )

    return SecurityTxtAssessment(
        present=False,
        url=None,
        contact=[],
        expires=None,
        policy=[],
        encryption=[],
        acknowledgments=[],
        preferred_languages=None,
        warnings=[],
    )


def check_robots_and_sitemaps(base_url: str, timeout: int = 10) -> RobotsAssessment:
    robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
    body, status, err = fetch_text(robots_url, timeout=timeout)
    if err or status is None or not (200 <= status < 300) or body is None:
        return RobotsAssessment(present=False, url=None, sitemaps=[])

    sitemaps: List[str] = []
    for line in body.splitlines():
        if line.lower().startswith("sitemap:"):
            sm = line.split(":", 1)[1].strip()
            if sm:
                sitemaps.append(sm)

    seen = set()
    sitemaps = [s for s in sitemaps if not (s in seen or seen.add(s))]

    return RobotsAssessment(present=True, url=robots_url, sitemaps=sitemaps)


def check_status_page(domain: str, base_url: str, timeout: int = 10) -> StatusPageAssessment:
    notes: List[str] = []
    reg = get_registrable_domain(domain)
    candidates = [
        f"https://status.{reg}/",
        urljoin(base_url.rstrip("/") + "/", "status"),
    ]

    for u in candidates:
        resp, err = fetch_url(u, timeout=timeout)
        if resp is None:
            continue
        status = resp.status_code
        if status and 200 <= status < 400:
            title = None
            try:
                if resp.text:
                    t, _ = extract_visible_text(resp.text)
                    title = t
            except Exception:
                title = None

            txt = (resp.text or "").lower()
            if "statuspage" in txt or "atlassian" in txt:
                notes.append("Looks like Atlassian Statuspage.")
            if "incident" in txt and "uptime" in txt:
                notes.append("Contains common status/incident keywords.")

            return StatusPageAssessment(True, u, status, title, notes)

    return StatusPageAssessment(False, None, None, None, [])


def fetch_xml(url: str, timeout: int = 10) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    resp, err = fetch_url(url, timeout=timeout)
    if resp is None:
        return None, None, err
    return resp.text or "", resp.status_code, None


def parse_sitemap_urls(sitemap_body: str) -> List[str]:
    """
    Forgiving parser to pull <loc> entries from sitemap XML text.
    Returns absolute URLs as strings.
    """
    if not sitemap_body:
        return []
    locs = re.findall(r"<loc>(.*?)</loc>", sitemap_body, flags=re.IGNORECASE | re.DOTALL)
    cleaned = []
    for l in locs:
        l2 = l.strip()
        if l2:
            cleaned.append(l2)
    seen = set()
    out = [u for u in cleaned if not (u in seen or seen.add(u))]
    return out


def likely_blog_url(url: str) -> bool:
    """
    Returns True if URL matches common blog/news/article patterns.
    """
    u = url.lower()
    for p in BLOG_EXCLUDE_COMPILED:
        if p.search(u):
            return True
    return False


# ----------------------------
# Page scanning and scoring
# ----------------------------

def scan_page(url: str, timeout: int) -> PageScanResult:
    resp, err = fetch_url(url, timeout=timeout)
    if resp is None:
        return PageScanResult(url, None, False, err, None, [], [], [], [], {}, None)

    status = resp.status_code
    ctype = resp.headers.get("Content-Type", "")

    if ctype and ("text/html" not in ctype and "application/xhtml+xml" not in ctype):
        return PageScanResult(clean_url(resp.url), status, True, f"Non-HTML content type: {ctype}", None, [], [], [], [], {}, None)

    title, text = extract_visible_text(resp.text or "")

    soc_hits = find_hits(SOC_PATTERNS, text)
    req_hits: List[str] = ["request_language_near_soc"] if soc_hits and has_nearby(text, SOC_PATTERNS, REQUEST_PATTERNS) else []
    login_hits: List[str] = ["login_language_near_soc"] if soc_hits and has_nearby(text, SOC_PATTERNS, LOGIN_PATTERNS) else []
    portal_hits = find_hits(PORTAL_PATTERNS, text)
    frameworks_found = detect_frameworks(text)
    sample = text[:450] if (soc_hits or portal_hits or frameworks_found) else None

    return PageScanResult(
        url=clean_url(resp.url),
        status_code=status,
        fetched=True,
        reason=None,
        title=title,
        soc_hits=soc_hits,
        request_gated_hits=req_hits,
        login_gated_hits=login_hits,
        trust_portal_hits=portal_hits,
        frameworks_found=frameworks_found,
        extracted_sample=sample,
    )


def assess_soc(pages: List[PageScanResult]) -> SocAssessment:
    notes: List[str] = []
    supporting: List[str] = []

    soc_pages = [p for p in pages if p.fetched and p.soc_hits]
    portal_pages = [p for p in pages if p.fetched and p.trust_portal_hits]
    request_pages = [p for p in soc_pages if p.request_gated_hits]
    login_pages = [p for p in soc_pages if p.login_gated_hits]

    soc_claimed = bool(soc_pages)

    if soc_claimed:
        if login_pages:
            access, conf = "login_required", 0.80
            notes.append("SOC language found, and nearby login/sign-in language suggests report access is gated.")
        elif request_pages:
            access, conf = "request_required", 0.85
            notes.append("SOC language found, and nearby request/NDA language suggests report is available upon request.")
        else:
            access, conf = "public", 0.75
            notes.append("SOC language is publicly stated. Report download may still require a request or portal access.")
    else:
        if portal_pages:
            access, conf = "unknown", 0.55
            notes.append("No SOC language found in scanned pages, but a trust portal provider signal was detected.")
        else:
            access, conf = "not_found", 0.20
            notes.append("No SOC language found in scanned trust/security/compliance pages.")

    evidence = "public_statement" if soc_claimed else ("portal_signal" if portal_pages else "none")

    for p in soc_pages:
        supporting.append(p.url)
    if not supporting:
        for p in portal_pages:
            supporting.append(p.url)

    seen = set()
    supporting = [u for u in supporting if not (u in seen or seen.add(u))]

    return SocAssessment(soc_claimed, access, evidence, round(conf, 2), notes, supporting)


def assess_frameworks(pages: List[PageScanResult]) -> Dict[str, FrameworkAssessment]:
    results: Dict[str, FrameworkAssessment] = {}
    fw_to_urls: Dict[str, List[str]] = {}

    for p in pages:
        if p.fetched and p.frameworks_found:
            for fw in p.frameworks_found.keys():
                fw_to_urls.setdefault(fw, []).append(p.url)

    for fw_name in FRAMEWORK_PATTERNS.keys():
        urls = fw_to_urls.get(fw_name, [])
        claimed = bool(urls)
        if claimed:
            conf, evidence, notes = 0.70, "public_statement", ["Detected a public marketing or documentation claim for this framework."]
            if any(re.search(r"(security|compliance|trust)", u, re.IGNORECASE) for u in urls):
                conf = min(0.85, conf + 0.10)
        else:
            conf, evidence, notes = 0.20, "none", ["No claim detected on scanned pages."]

        seen = set()
        urls = [u for u in urls if not (u in seen or seen.add(u))]

        results[fw_name] = FrameworkAssessment(fw_name, claimed, round(conf, 2), evidence, notes, urls)

    return results


def should_print_page(status: object, fetched: bool, debug: bool) -> bool:
    if debug:
        return True
    if not fetched:
        return True
    if isinstance(status, int):
        if 200 <= status < 400:
            return True
        if status in (401, 403):
            return True
    return False


# ----------------------------
# Snapshot runner with sitemap-driven discovery excluding blogs
# ----------------------------

def run_snapshot(domain: str, timeout: int, max_pages: int, sitemap_keyword_cap: int = 30) -> VendorSnapshot:
    """
    sitemap_keyword_cap: max number of sitemap-derived URLs that include security keywords to add
    """
    domain = normalize_domain(domain)
    base_url = build_base_url(domain)

    pages: List[PageScanResult] = []
    homepage_url = base_url.rstrip("/") + "/"
    home = scan_page(homepage_url, timeout=timeout)
    pages.append(home)

    # Early robots + sitemap check to seed discovery
    discovered: List[str] = []
    robots_info = check_robots_and_sitemaps(base_url, timeout=timeout)
    sitemap_candidates: List[str] = []
    if robots_info.present and robots_info.sitemaps:
        # fetch each sitemap and parse <loc> entries; stop if many found
        for sm in robots_info.sitemaps:
            try:
                body, status, err = fetch_xml(sm, timeout=timeout)
            except Exception:
                body, status, err = None, None, "fetch error"
            if body and status and 200 <= status < 400:
                urls = parse_sitemap_urls(body)
                # filter sitemap urls for security/compliance keywords to avoid huge lists
                for u in urls:
                    low = u.lower()
                    if likely_blog_url(low):
                        continue
                    if any(k in low for k in ["security", "trust", "compliance", "privacy", "soc", "pci", "gdpr", "iso", "status"]):
                        sitemap_candidates.append(u)
                        if len(sitemap_candidates) >= sitemap_keyword_cap:
                            break
            if len(sitemap_candidates) >= sitemap_keyword_cap:
                break

    # If homepage had discoverable links, add them too
    if home.fetched and home.status_code and 200 <= home.status_code < 400:
        resp, _ = fetch_url(home.url, timeout=timeout)
        if resp is not None and (resp.text or ""):
            discovered = discover_links_from_homepage(resp.text, home.url, domain)

    # Build base candidate list (same default paths + common subdomains)
    candidates = []
    for u in generate_candidate_urls(base_url, domain) + discovered + sitemap_candidates:
        if u not in candidates:
            candidates.append(u)

    candidates = [u for u in candidates if u.rstrip("/") != homepage_url.rstrip("/")]

    # limit pages scanned to max_pages
    for u in candidates[: max(0, max_pages - 1)]:
        pages.append(scan_page(u, timeout=timeout))

    soc = assess_soc(pages)
    frameworks = assess_frameworks(pages)

    dnssec_status = check_dnssec_status(domain)

    spf_present, spf_record = check_spf(domain)
    spf_assessment = assess_spf(spf_present, spf_record)

    dmarc_present, dmarc_policy, dmarc_raw = check_dmarc(domain)
    dmarc_assessment = assess_dmarc(dmarc_present, dmarc_policy, dmarc_raw)

    tls_version, tls_ok, cert_valid, not_before, not_after, days_until_expiry, tls11_allowed, tls10_allowed = check_tls(domain, timeout=timeout)

    hsts_assessment = check_hsts(base_url, timeout=timeout)

    security_txt = check_security_txt(base_url, timeout=timeout)
    robots = robots_info  # we already collected robots earlier
    status_page = check_status_page(domain, base_url, timeout=timeout)

    dns_tls = DnsTlsAssessment(
        dnssec_status=dnssec_status,
        spf=spf_assessment,
        dmarc=dmarc_assessment,
        tls_version=tls_version,
        tls_ok_1_2_plus=tls_ok,
        tls_1_1_allowed=tls11_allowed,
        tls_1_0_allowed=tls10_allowed,
        tls_cert_valid=cert_valid,
        tls_cert_not_before=not_before,
        tls_cert_not_after=not_after,
        tls_cert_days_until_expiry=days_until_expiry,
        hsts=hsts_assessment,
        security_txt=security_txt,
        robots=robots,
        status_page=status_page,
    )

    return VendorSnapshot(
        vendor_domain=domain,
        base_url=base_url,
        scanned_at_utc=datetime.now(timezone.utc).isoformat(),
        pages_scanned=len(pages),
        pages=pages,
        soc=soc,
        frameworks=frameworks,
        dns_tls=dns_tls,
    )


# ----------------------------
# Output
# ----------------------------

def print_summary(snapshot: VendorSnapshot, debug: bool = False) -> None:
    print(f"Vendor: {snapshot.vendor_domain}")
    print(f"Scanned: {snapshot.scanned_at_utc}")
    print(f"Pages scanned: {snapshot.pages_scanned}")
    print()

    soc = snapshot.soc
    print("SOC Assessment")
    print(f"  Claimed: {soc.soc_claimed}")
    print(f"  Access: {soc.access}")
    print(f"  Evidence: {soc.evidence}")
    print(f"  Confidence: {soc.confidence}")
    for n in soc.notes:
        print(f"  Note: {n}")
    if soc.supporting_urls:
        print("  Supporting URLs:")
        for u in soc.supporting_urls:
            print(f"    - {u}")
    print()

    print("Framework Claims (public statements)")
    for fw_name, fw in snapshot.frameworks.items():
        status = "Yes" if fw.claimed else "No"
        print(f"  {fw_name}: {status} (confidence {fw.confidence})")
        if fw.claimed and fw.supporting_urls:
            for u in fw.supporting_urls[:3]:
                print(f"    - {u}")
    print()

    d = snapshot.dns_tls
    print("DNS, Email, TLS, and Web Hygiene Checks")
    print(f"  DNSSEC status: {d.dnssec_status}")

    print(f"  SPF present: {d.spf.present}")
    if d.spf.present and d.spf.summary:
        print(f"    SPF summary: {d.spf.summary}")
    if d.spf.warnings:
        for w in d.spf.warnings[:5]:
            print(f"    SPF warning: {w}")

    print(f"  DMARC present: {d.dmarc.present}")
    if d.dmarc.present:
        print(f"    DMARC policy: {d.dmarc.policy}")
        if d.dmarc.pct is not None:
            print(f"    DMARC pct: {d.dmarc.pct}")
        print(f"    DMARC rua present: {d.dmarc.rua_present}")
        print(f"    DMARC ruf present: {d.dmarc.ruf_present}")
    if d.dmarc.warnings:
        for w in d.dmarc.warnings[:5]:
            print(f"    DMARC warning: {w}")

    print(f"  TLS version: {d.tls_version}")
    print(f"  TLS >= 1.2: {d.tls_ok_1_2_plus}")
    print(f"  TLS 1.1 allowed: {d.tls_1_1_allowed}")
    print(f"  TLS 1.0 allowed: {d.tls_1_0_allowed}")
    print(f"  TLS cert currently valid: {d.tls_cert_valid}")
    if d.tls_cert_not_before or d.tls_cert_not_after:
        print(f"    cert notBefore: {d.tls_cert_not_before}")
        print(f"    cert notAfter: {d.tls_cert_not_after}")
    if d.tls_cert_days_until_expiry is not None:
        print(f"    cert days until expiry: {d.tls_cert_days_until_expiry}")

    print(f"  HSTS present: {d.hsts.present}")
    if d.hsts.present:
        print(f"    HSTS max-age: {d.hsts.max_age}")
        print(f"    HSTS includeSubDomains: {d.hsts.include_subdomains}")
        print(f"    HSTS preload: {d.hsts.preload}")

    print(f"  security.txt present: {d.security_txt.present}")
    if d.security_txt.present:
        print(f"    security.txt url: {d.security_txt.url}")
        if d.security_txt.contact:
            for c in d.security_txt.contact[:3]:
                print(f"    security.txt contact: {c}")
        if d.security_txt.expires:
            print(f"    security.txt expires: {d.security_txt.expires}")
        if d.security_txt.preferred_languages:
            print(f"    security.txt preferred-languages: {d.security_txt.preferred_languages}")
        if d.security_txt.warnings:
            for w in d.security_txt.warnings[:5]:
                print(f"    security.txt warning: {w}")

    print(f"  robots.txt present: {d.robots.present}")
    if d.robots.present:
        print(f"    robots.txt url: {d.robots.url}")
        if d.robots.sitemaps:
            for sm in d.robots.sitemaps[:5]:
                print(f"    sitemap: {sm}")

    print(f"  Status page present: {d.status_page.present}")
    if d.status_page.present:
        print(f"    status url: {d.status_page.url}")
        print(f"    status code: {d.status_page.status_code}")
        if d.status_page.title:
            print(f"    status title: {d.status_page.title}")
        for n in d.status_page.notes[:5]:
            print(f"    status note: {n}")

    print()
    print("Page Results")
    for p in snapshot.pages:
        st = p.status_code if p.status_code is not None else "N/A"
        if not should_print_page(st, p.fetched, debug):
            continue

        fetched = "ok" if p.fetched else "fail"
        title = f" | {p.title}" if p.title else ""
        soc_flag = " | SOC" if p.soc_hits else ""
        portal_flag = " | Portal" if p.trust_portal_hits else ""
        gated_flag = " | Login-gated" if p.login_gated_hits else (" | Request-gated" if p.request_gated_hits else "")
        fw_flag = " | " + ", ".join(sorted(p.frameworks_found.keys())) if p.frameworks_found else ""

        print(f"  - [{fetched}] {st} {p.url}{title}{soc_flag}{portal_flag}{gated_flag}{fw_flag}")
        if p.reason:
            print(f"      reason: {p.reason}")


def snapshot_to_json(snapshot: VendorSnapshot) -> str:
    return json.dumps(asdict(snapshot), indent=2, sort_keys=False)


# ----------------------------
# CLI
# ----------------------------

def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser(description="Vendor Risk Snapshot (framework claims + DNS/email/TLS/hygiene checks)")
    p.add_argument("--domain", required=True, help="Vendor domain, example: example.com")
    p.add_argument("--timeout", type=int, default=12, help="HTTP timeout seconds")
    p.add_argument("--max-pages", type=int, default=15, help="Max number of pages to scan")
    p.add_argument("--json", dest="json_path", default=None, help="Write full JSON output to file")
    p.add_argument("--debug", action="store_true", help="Show all scanned pages including 404s")
    args = p.parse_args(argv)

    snap = run_snapshot(args.domain, timeout=args.timeout, max_pages=args.max_pages)
    print_summary(snap, debug=args.debug)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            f.write(snapshot_to_json(snap))
        print()
        print(f"Wrote JSON: {args.json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
