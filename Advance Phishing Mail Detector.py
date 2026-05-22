import argparse
import base64
import email
import hashlib
import html
import ipaddress
import json
import mimetypes
import os
import re
import time
import unicodedata
import urllib.parse
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from io import BytesIO
from xml.etree import ElementTree

import requests
from bs4 import BeautifulSoup

# --- Graceful imports for optional libraries ---
try:
    import whois

    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import pdfplumber
    import docx

    ATTACHMENT_PARSING_AVAILABLE = True
except ImportError:
    ATTACHMENT_PARSING_AVAILABLE = False

try:
    from PIL import Image
    from pyzbar.pyzbar import decode as qr_decode
    import pytesseract

    IMAGE_SCANNING_AVAILABLE = True
except ImportError:
    IMAGE_SCANNING_AVAILABLE = False

try:
    import tldextract

    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    from oletools.olevba import VBA_Parser

    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False


# -------------------------------
# CONFIGURATION
# -------------------------------
API_KEY = os.getenv("VT_API_KEY")
VT_AVAILABLE = bool(API_KEY)

CONFIG = {
    "weights": {
        "mismatch_return_path": 2,
        "mismatch_reply_to": 2,
        "dmarc_fail": 7,
        "dmarc_weak_or_missing": 1,
        "spf_fail": 2,
        "spf_not_found": 1,
        "dkim_fail": 2,
        "dkim_not_found": 1,
        "auth_alignment_mismatch": 3,
        "compauth_fail": 3,
        "display_name_domain_mismatch": 4,
        "brand_impersonation": 3,
        "homograph_attack": 5,
        "malicious_link": 3,
        "malicious_domain": 4,
        "malicious_ip": 3,
        "malicious_attachment": 10,
        "suspicious_attachment": 4,
        "deceptive_link": 3,
        "suspicious_url_feature": 2,
        "abused_service_link": 2,
        "recent_domain": 5,
        "javascript_present": 2,
        "credential_form": 4,
        "urgent_keywords": 1,
        "high_risk_keywords": 4,
        "impersonation_keywords": 3,
    },
    "settings": {
        "domain_age_threshold_days": 90,
        "default_vt_delay_seconds": 16,
        "default_max_vt_items": 40,
    },
    "lists": {
        "abused_legit_services": [
            "docs.google.com",
            "drive.google.com",
            "onedrive.live.com",
            "dropbox.com",
            "forms.gle",
            "1drv.ms",
            "sharepoint.com",
            "storage.googleapis.com",
            "github.io",
            "pages.dev",
            "workers.dev",
        ],
        "high_risk_keywords": [
            "wire transfer",
            "gift card",
            "crypto",
            "bitcoin",
            "urgent payment",
            "payroll",
            "bank account",
        ],
        "impersonated_brands": [
            "microsoft",
            "office 365",
            "paypal",
            "amazon",
            "apple",
            "google",
            "docusign",
            "dropbox",
            "coinbase",
            "netflix",
            "adobe",
            "github",
            "opensea",
            "looksrare",
        ],
        "brand_domains": {
            "microsoft": ["microsoft.com", "office.com", "live.com"],
            "office 365": ["microsoft.com", "office.com"],
            "paypal": ["paypal.com"],
            "amazon": ["amazon.com"],
            "apple": ["apple.com"],
            "google": ["google.com"],
            "docusign": ["docusign.com"],
            "dropbox": ["dropbox.com"],
            "coinbase": ["coinbase.com"],
            "netflix": ["netflix.com"],
            "adobe": ["adobe.com"],
            "github": ["github.com"],
            "opensea": ["opensea.io"],
            "looksrare": ["looksrare.org"],
        },
        "risky_extensions": [
            ".exe",
            ".scr",
            ".bat",
            ".cmd",
            ".com",
            ".ps1",
            ".vbs",
            ".vbe",
            ".js",
            ".jse",
            ".wsf",
            ".hta",
            ".lnk",
            ".iso",
            ".img",
            ".jar",
            ".msi",
            ".dll",
            ".chm",
            ".one",
            ".docm",
            ".xlsm",
            ".pptm",
            ".xlam",
            ".xll",
            ".html",
            ".htm",
            ".svg",
        ],
        "shorteners": [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "cutt.ly",
            "rebrand.ly",
            "shorturl.at",
            "lnkd.in",
        ],
        "redirect_param_names": [
            "url",
            "u",
            "uri",
            "redirect",
            "redirect_uri",
            "target",
            "to",
            "next",
            "continue",
            "return",
            "returnurl",
            "r",
        ],
        "reference_url_hosts": [
            "schemas.openxmlformats.org",
            "schemas.microsoft.com",
            "purl.org",
            "www.w3.org",
            "www.wps.cn",
            "schemas.google.com",
        ],
    },
}


# -------------------------------
# COLOR & FORMATTING CONSTANTS
# -------------------------------
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"
CHECK = "[OK]"
CROSS = "[!!]"
INFO = "[i]"
ANSI_RE = re.compile(r"\033\[[0-9;]*m")


# -------------------------------
# BASIC NORMALIZATION
# -------------------------------
def strip_ansi(value):
    return ANSI_RE.sub("", value)


def decode_header_value(value):
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def unfold_header(value):
    return re.sub(r"\r?\n[ \t]+", " ", decode_header_value(value)).strip()


def unique_list(values):
    out, seen = [], set()
    for value in values:
        if value is None:
            continue
        key = json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value)
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out


def get_header_values(msg, name):
    return [unfold_header(v) for v in msg.get_all(name, [])]


def get_first_header(msg, name):
    values = get_header_values(msg, name)
    return values[0] if values else None


def normalize_domain(domain):
    if not domain:
        return None

    domain = html.unescape(str(domain)).strip().lower()
    if "://" in domain:
        parsed = urllib.parse.urlsplit(domain)
        domain = parsed.hostname or domain

    domain = domain.strip(" <>[]{}()\"'`")
    domain = domain.rstrip(".,;:")
    if domain.startswith("@"):
        domain = domain[1:]
    if domain.endswith("."):
        domain = domain[:-1]

    # Remove a port from hostname values, but do not break IPv6 literals.
    if domain.count(":") == 1 and re.search(r":\d+$", domain):
        domain = domain.rsplit(":", 1)[0]

    if not domain or "@" in domain or "/" in domain:
        return None

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    labels = domain.split(".")
    if len(labels) < 2:
        return None
    if any(not label or len(label) > 63 for label in labels):
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        return None
    return domain


def normalize_email_address(address):
    if not address:
        return None
    address = decode_header_value(address).strip().strip("<>\"' ")
    address = address.rstrip(".,;")
    if "@" not in address:
        return None
    local, domain = address.rsplit("@", 1)
    domain = normalize_domain(domain)
    local = local.strip().strip("\"").lower()
    if not local or not domain:
        return None
    return f"{local}@{domain}"


def parse_mailbox_headers(msg, header_name):
    raw_values = get_header_values(msg, header_name)
    mailboxes = []
    for display_name, address in getaddresses(raw_values):
        normalized = normalize_email_address(address)
        if not normalized:
            continue
        domain = normalized.rsplit("@", 1)[1]
        mailboxes.append(
            {
                "display_name": decode_header_value(display_name).strip().strip("\""),
                "address": normalized,
                "domain": domain,
                "raw_header": header_name,
            }
        )
    return unique_list(mailboxes)


def get_primary_mailbox(msg, header_name):
    mailboxes = parse_mailbox_headers(msg, header_name)
    return mailboxes[0] if mailboxes else None


def registered_domain(domain):
    domain = normalize_domain(domain)
    if not domain:
        return None
    if TLDEXTRACT_AVAILABLE:
        ext = tldextract.extract(domain)
        reg = getattr(ext, "top_domain_under_public_suffix", None) or getattr(ext, "registered_domain", None)
        return reg or domain
    labels = domain.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def domains_align(left, right):
    left_reg = registered_domain(left)
    right_reg = registered_domain(right)
    return bool(left_reg and right_reg and left_reg == right_reg)


def clean_url(url):
    if not url:
        return None
    url = html.unescape(str(url)).strip()
    url = url.strip("<>\"'")
    while url and url[-1] in ".,;":
        url = url[:-1]
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return None
    parsed = urllib.parse.urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return urllib.parse.urlunsplit(parsed)


def normalize_url(url):
    url = clean_url(url)
    if not url:
        return None
    parsed = urllib.parse.urlsplit(url)
    host = normalize_domain(parsed.hostname)
    if not host:
        return url
    netloc = host
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth = f"{auth}:{parsed.password}"
        netloc = f"{auth}@{netloc}"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def url_host(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        return normalize_domain(parsed.hostname)
    except Exception:
        return None


def defang(value):
    if not value:
        return value
    return (
        str(value)
        .replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )


def is_reference_url(url):
    host = url_host(url)
    if not host:
        return False
    if host in CONFIG["lists"]["reference_url_hosts"]:
        return True
    if host.endswith(".w3.org") or host.endswith(".openxmlformats.org"):
        return True
    return False


def filter_actionable_urls(urls):
    actionable, ignored = [], []
    for url in unique_list(urls):
        cleaned = clean_url(url)
        if not cleaned:
            continue
        if is_reference_url(cleaned):
            ignored.append(cleaned)
        else:
            actionable.append(cleaned)
    return unique_list(actionable), unique_list(ignored)


def brand_mentions(text):
    if not text:
        return []
    compact_text = re.sub(r"[^a-z0-9]+", "", text.lower())
    mentions = []
    for brand in CONFIG["lists"]["impersonated_brands"]:
        compact_brand = re.sub(r"[^a-z0-9]+", "", brand.lower())
        if compact_brand and compact_brand in compact_text:
            mentions.append(brand)
    return unique_list(mentions)


def brand_domain_mismatches(domain):
    domain = normalize_domain(domain)
    if not domain:
        return []
    compact_domain = re.sub(r"[^a-z0-9]+", "", domain.lower())
    mismatches = []
    for brand, official_domains in CONFIG["lists"]["brand_domains"].items():
        compact_brand = re.sub(r"[^a-z0-9]+", "", brand.lower())
        if not compact_brand or compact_brand not in compact_domain:
            continue
        if not any(domains_align(domain, official) for official in official_domains):
            mismatches.append(
                {
                    "brand": brand,
                    "domain": domain,
                    "official_domains": official_domains,
                }
            )
    return mismatches


def normalize_ip(candidate):
    if not candidate:
        return None
    candidate = str(candidate).strip().strip("[]()<>.,;")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def is_public_ip(ip_value):
    try:
        return ipaddress.ip_address(ip_value).is_global
    except ValueError:
        return False


def extract_ips(text, public_only=False):
    if not text:
        return []

    candidates = set()
    candidates.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    candidates.update(re.findall(r"\[([0-9A-Fa-f:]{2,})\]", text))
    candidates.update(re.findall(r"(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{1,4}:){2,}[A-Fa-f0-9:]{1,}(?![A-Fa-f0-9:])", text))

    results = []
    for candidate in candidates:
        ip_value = normalize_ip(candidate)
        if not ip_value:
            continue
        if public_only and not is_public_ip(ip_value):
            continue
        results.append(ip_value)
    return sorted(set(results), key=lambda value: (":" in value, value))


def hashes_for_bytes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def timestamp_to_iso(timestamp_value):
    if not timestamp_value:
        return None
    try:
        return datetime.fromtimestamp(int(timestamp_value), tz=timezone.utc).isoformat()
    except Exception:
        return None


# -------------------------------
# EMAIL PARSING
# -------------------------------
def parse_eml_file(file_path):
    with open(file_path, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    header_text = "".join(f"{key}: {unfold_header(value)}\n" for key, value in msg.items())
    body, html_body, attachments, images = "", "", [], []

    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            content_type = part.get_content_type() or "application/octet-stream"
            disposition = part.get_content_disposition()
            filename = decode_header_value(part.get_filename() or "").strip() or None
            payload = part.get_payload(decode=True)
            if payload is None:
                try:
                    content = part.get_content()
                    payload = content.encode(part.get_content_charset() or "utf-8", errors="ignore") if isinstance(content, str) else b""
                except Exception:
                    payload = b""

            is_attachment = bool(
                disposition == "attachment"
                or filename
                or content_type.startswith("application/")
                or content_type in {"message/rfc822", "application/octet-stream"}
            )

            if is_attachment:
                attachments.append(
                    {
                        "filename": filename or "unknown",
                        "content_type": content_type,
                        "content_disposition": disposition or "",
                        "data": payload or b"",
                    }
                )
            elif content_type.startswith("image/"):
                images.append(
                    {
                        "filename": filename or "inline-image",
                        "content_type": content_type,
                        "data": payload or b"",
                    }
                )
            elif content_type == "text/plain":
                body += decode_part_text(part, payload)
            elif content_type == "text/html":
                html_body += decode_part_text(part, payload)
        except Exception as exc:
            print(f"{YELLOW}Warning: Could not process a MIME part. Error: {exc}{RESET}")

    return msg, header_text, body, html_body, attachments, images


def decode_part_text(part, payload):
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except Exception:
        return payload.decode("utf-8", errors="replace")


# -------------------------------
# HEADER ANALYSIS
# -------------------------------
def parse_tag_value_header(value):
    tags = {}
    for item in unfold_header(value).split(";"):
        if "=" not in item:
            continue
        key, val = item.split("=", 1)
        tags[key.strip().lower()] = val.strip()
    return tags


def parse_authentication_results(msg):
    parsed_headers = []
    for header_name in ("Authentication-Results", "ARC-Authentication-Results"):
        for raw_value in get_header_values(msg, header_name):
            text = unfold_header(raw_value)
            result_values = {}
            for key in ("spf", "dkim", "dmarc", "arc", "compauth", "dara"):
                matches = re.findall(rf"\b{re.escape(key)}\s*=\s*([A-Za-z0-9_-]+)", text, re.IGNORECASE)
                if matches:
                    result_values[key] = matches[-1].lower()

            params = {}
            for param in (
                "smtp.mailfrom",
                "smtp.rcpttodomain",
                "header.from",
                "header.d",
                "header.i",
                "client-ip",
                "action",
                "reason",
            ):
                pattern = rf"(?<![\w.]){re.escape(param)}\s*=\s*([^;\s\)]+)"
                values = [v.strip(" <>\"'") for v in re.findall(pattern, text, re.IGNORECASE)]
                if values:
                    params[param] = unique_list(values)

            sender_ip_matches = re.findall(
                r"sender\s+ip(?:\s+address)?(?:\s+is|:)?\s*([0-9A-Fa-f:.]+)",
                text,
                re.IGNORECASE,
            )
            sender_ips = extract_ips(" ".join(sender_ip_matches), public_only=True)
            sender_ips.extend(extract_ips(text, public_only=True))
            sender_ips = unique_list(sender_ips)

            parsed_headers.append(
                {
                    "header_name": header_name,
                    "results": result_values,
                    "params": params,
                    "sender_ips": sender_ips,
                    "raw": text,
                }
            )
    return parsed_headers


def choose_primary_auth(auth_results):
    for item in auth_results:
        if item["header_name"].lower() == "authentication-results":
            return item
    return auth_results[0] if auth_results else {"results": {}, "params": {}, "sender_ips": [], "raw": ""}


def parse_microsoft_security_headers(msg):
    ms_header_names = [
        "X-Forefront-Antispam-Report",
        "X-Microsoft-Antispam",
        "X-MS-Exchange-Organization-Antispam-Report",
    ]
    fields = defaultdict(list)
    raw_headers = []

    for name in ms_header_names:
        for raw_value in get_header_values(msg, name):
            raw_headers.append({"name": name, "raw": raw_value})
            for item in raw_value.split(";"):
                item = item.strip()
                if ":" not in item:
                    continue
                key, value = item.split(":", 1)
                key = key.strip().upper()
                value = value.strip()
                if key and value:
                    fields[key].append(value)

    direct_headers = {}
    for name in [
        "X-MS-Exchange-Organization-SCL",
        "X-MS-Exchange-Organization-PCL",
        "X-MS-Exchange-Organization-BCL",
        "X-MS-Exchange-Organization-AuthSource",
        "X-MS-Exchange-Organization-AuthAs",
        "X-MS-Exchange-Organization-SenderIdResult",
        "X-MS-Exchange-Organization-MessageDirectionality",
        "X-Sender-IP",
        "X-Originating-IP",
    ]:
        values = get_header_values(msg, name)
        if values:
            direct_headers[name] = values

    return {
        "raw_headers": raw_headers,
        "fields": {key: unique_list(values) for key, values in fields.items()},
        "direct_headers": direct_headers,
    }


def parse_received_headers(msg):
    received = []
    for index, raw_value in enumerate(get_header_values(msg, "Received"), start=1):
        text = unfold_header(raw_value)
        from_match = re.search(r"\bfrom\s+([^\s(;]+)", text, re.IGNORECASE)
        by_match = re.search(r"\bby\s+([^\s(;]+)", text, re.IGNORECASE)
        with_match = re.search(r"\bwith\s+([A-Za-z0-9_./-]+)", text, re.IGNORECASE)
        tls_match = re.search(r"version=([^,\s)]+)", text, re.IGNORECASE)
        cipher_match = re.search(r"cipher=([^,\s)]+)", text, re.IGNORECASE)

        date_text = None
        date_iso = None
        if ";" in text:
            date_text = text.rsplit(";", 1)[-1].strip()
            try:
                date_iso = parsedate_to_datetime(date_text).astimezone(timezone.utc).isoformat()
            except Exception:
                date_iso = None

        all_ips = extract_ips(text, public_only=False)
        public_ips = [ip for ip in all_ips if is_public_ip(ip)]
        received.append(
            {
                "hop": index,
                "from": from_match.group(1) if from_match else None,
                "by": by_match.group(1) if by_match else None,
                "with": with_match.group(1) if with_match else None,
                "tls_version": tls_match.group(1) if tls_match else None,
                "cipher": cipher_match.group(1) if cipher_match else None,
                "ips": all_ips,
                "public_ips": public_ips,
                "date": date_text,
                "date_utc": date_iso,
                "raw": text,
            }
        )
    return received


def parse_dkim_signatures(msg):
    signatures = []
    for raw_value in get_header_values(msg, "DKIM-Signature"):
        tags = parse_tag_value_header(raw_value)
        domain = normalize_domain(tags.get("d"))
        signatures.append(
            {
                "domain": domain,
                "selector": tags.get("s"),
                "algorithm": tags.get("a"),
                "canonicalization": tags.get("c"),
                "signed_headers": [h.strip() for h in tags.get("h", "").split(":") if h.strip()],
                "raw": raw_value,
            }
        )
    return signatures


def parse_received_spf(msg):
    values = []
    for raw_value in get_header_values(msg, "Received-SPF"):
        result_match = re.match(r"([A-Za-z0-9_-]+)", raw_value)
        values.append(
            {
                "result": result_match.group(1).lower() if result_match else None,
                "client_ip": (re.search(r"client-ip=([^;\s]+)", raw_value, re.IGNORECASE) or [None, None])[1],
                "envelope_from": (re.search(r"(?:envelope-from|smtp.mailfrom)=([^;\s]+)", raw_value, re.IGNORECASE) or [None, None])[1],
                "helo": (re.search(r"helo=([^;\s]+)", raw_value, re.IGNORECASE) or [None, None])[1],
                "raw": raw_value,
            }
        )
    return values


def analyze_header(msg):
    from_box = get_primary_mailbox(msg, "From")
    return_path_box = get_primary_mailbox(msg, "Return-Path")
    reply_to_box = get_primary_mailbox(msg, "Reply-To")
    to_boxes = parse_mailbox_headers(msg, "To")
    cc_boxes = parse_mailbox_headers(msg, "Cc")
    auth_results = parse_authentication_results(msg)
    primary_auth = choose_primary_auth(auth_results)
    microsoft_headers = parse_microsoft_security_headers(msg)
    received_path = parse_received_headers(msg)
    dkim_signatures = parse_dkim_signatures(msg)
    received_spf = parse_received_spf(msg)

    auth = primary_auth.get("results", {})
    params = primary_auth.get("params", {})
    from_domain = from_box["domain"] if from_box else None
    display_name_claimed_emails = []
    display_name_claimed_domains = []
    if from_box and from_box.get("display_name"):
        display_name = from_box["display_name"]
        display_name_claimed_emails = [normalize_email_address(addr) for _, addr in getaddresses([display_name])]
        display_name_claimed_emails = unique_list([addr for addr in display_name_claimed_emails if addr])
        display_name_claimed_domains = [addr.rsplit("@", 1)[1] for addr in display_name_claimed_emails]
        display_name_claimed_domains.extend([normalize_domain(match) for match in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", display_name, re.IGNORECASE)])
        display_name_claimed_domains = unique_list([domain for domain in display_name_claimed_domains if domain])
    display_name_domain_mismatch = None
    if from_domain and display_name_claimed_domains:
        display_name_domain_mismatch = not any(domains_align(from_domain, domain) for domain in display_name_claimed_domains)
    display_name_brand_mentions = brand_mentions(from_box.get("display_name") if from_box else "")
    display_name_brand_mismatch = False
    if from_domain and display_name_brand_mentions:
        for brand in display_name_brand_mentions:
            official_domains = CONFIG["lists"]["brand_domains"].get(brand, [])
            if official_domains and not any(domains_align(from_domain, official) for official in official_domains):
                display_name_brand_mismatch = True
                break

    smtp_mailfrom_domains = [normalize_domain(v.split("@")[-1]) for v in params.get("smtp.mailfrom", [])]
    header_from_domains = [normalize_domain(v.split("@")[-1]) for v in params.get("header.from", [])]
    dkim_domains = [normalize_domain(v) for v in params.get("header.d", [])]
    dkim_domains.extend([item.get("domain") for item in dkim_signatures if item.get("domain")])
    dkim_domains = unique_list([d for d in dkim_domains if d])

    spf_aligned = None
    if from_domain and smtp_mailfrom_domains:
        spf_aligned = any(domains_align(from_domain, domain) for domain in smtp_mailfrom_domains if domain)

    dkim_aligned = None
    if from_domain and dkim_domains:
        dkim_aligned = any(domains_align(from_domain, domain) for domain in dkim_domains if domain)

    return_path_mismatch = None
    if from_box and return_path_box:
        return_path_mismatch = from_box["address"] != return_path_box["address"]

    reply_to_mismatch = None
    if from_box and reply_to_box:
        reply_to_mismatch = from_box["address"] != reply_to_box["address"]

    sender_ips = unique_list(
        primary_auth.get("sender_ips", [])
        + [ip for hop in received_path for ip in hop.get("public_ips", [])]
        + extract_ips(" ".join(microsoft_headers["direct_headers"].get("X-Sender-IP", [])), public_only=True)
        + extract_ips(" ".join(microsoft_headers["direct_headers"].get("X-Originating-IP", [])), public_only=True)
    )

    return {
        "From": from_box,
        "Return-Path": return_path_box,
        "Reply-To": reply_to_box,
        "To": to_boxes,
        "Cc": cc_boxes,
        "From Address": from_box["address"] if from_box else None,
        "Return-Path Address": return_path_box["address"] if return_path_box else None,
        "Reply-To Address": reply_to_box["address"] if reply_to_box else None,
        "Return-Path Mismatch": return_path_mismatch,
        "Reply-To Mismatch": reply_to_mismatch,
        "SPF Result": auth.get("spf", "not found"),
        "DKIM Result": auth.get("dkim", "not found"),
        "DMARC Result": auth.get("dmarc", "not found"),
        "CompAuth Result": auth.get("compauth"),
        "CompAuth Reason": (params.get("reason") or [None])[0],
        "Auth Action": (params.get("action") or [None])[0],
        "SPF MailFrom Domains": unique_list([d for d in smtp_mailfrom_domains if d]),
        "Header From Domains": unique_list([d for d in header_from_domains if d]),
        "DKIM Domains": dkim_domains,
        "Display Name Claimed Emails": display_name_claimed_emails,
        "Display Name Claimed Domains": display_name_claimed_domains,
        "Display Name Domain Mismatch": display_name_domain_mismatch,
        "Display Name Brand Mentions": display_name_brand_mentions,
        "Display Name Brand Mismatch": display_name_brand_mismatch,
        "SPF Aligned": spf_aligned,
        "DKIM Aligned": dkim_aligned,
        "Sender IPs": sender_ips,
        "Authentication-Results": auth_results,
        "Primary Authentication-Results": primary_auth,
        "Microsoft Security Headers": microsoft_headers,
        "Received Path": received_path,
        "DKIM Signatures": dkim_signatures,
        "Received-SPF": received_spf,
        "Subject": get_first_header(msg, "Subject"),
        "Message-ID": get_first_header(msg, "Message-ID"),
        "Date": get_first_header(msg, "Date"),
    }


def analyze_domain_for_spoofing(domain):
    if not domain:
        return {}
    normalized = normalize_domain(domain)
    findings = {
        "is_homograph_attack": False,
        "punycode_version": None,
        "unicode_normalized": unicodedata.normalize("NFKC", domain),
        "registered_domain": registered_domain(normalized),
    }
    if domain != unicodedata.normalize("NFKC", domain):
        findings["is_homograph_attack"] = True
    try:
        punycode = str(domain).encode("idna").decode("ascii")
        if punycode.startswith("xn--") or ".xn--" in punycode:
            findings["punycode_version"] = punycode
            findings["is_homograph_attack"] = True
    except UnicodeError:
        findings["is_homograph_attack"] = True
    return findings


def check_domain_age(domain):
    if not WHOIS_AVAILABLE or not domain:
        return None
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            return (datetime.now() - creation_date).days
    except Exception:
        return None
    return None


# -------------------------------
# URL AND CONTENT ANALYSIS
# -------------------------------
def extract_urls_from_text(text):
    if not text:
        return []
    urls = []
    for match in re.findall(r"https?://[^\s<>\"']+", text, re.IGNORECASE):
        cleaned = clean_url(match)
        if cleaned:
            urls.append(cleaned)
    return unique_list(urls)


def extract_urls_from_bytes(data):
    if not data:
        return []
    urls = []
    for match in re.findall(rb"https?://[^\s<>\"']+", data, re.IGNORECASE):
        try:
            cleaned = clean_url(match.decode("utf-8", errors="ignore"))
            if cleaned:
                urls.append(cleaned)
        except Exception:
            continue
    return unique_list(urls)


def analyze_url(url, source, link_text=None):
    normalized = normalize_url(url)
    parsed = urllib.parse.urlsplit(normalized or url)
    host = normalize_domain(parsed.hostname)
    features = []

    if parsed.username or parsed.password:
        features.append("URL contains user-info before host")
    if host and host in CONFIG["lists"]["shorteners"]:
        features.append("URL uses a known shortener")
    if host and host.startswith("xn--") or (host and ".xn--" in host):
        features.append("URL host contains punycode")
    if parsed.hostname and normalize_ip(parsed.hostname):
        features.append("URL uses an IP literal as host")
    if host and len(host.split(".")) >= 5:
        features.append("URL has many subdomain levels")
    for mismatch in brand_domain_mismatches(host):
        features.append(
            f"URL domain contains brand token '{mismatch['brand']}' but is not an official brand domain"
        )

    query = urllib.parse.parse_qs(parsed.query)
    for key, values in query.items():
        if key.lower() in CONFIG["lists"]["redirect_param_names"]:
            if any(clean_url(urllib.parse.unquote(v)) for v in values):
                features.append(f"URL carries nested redirect parameter '{key}'")

    if host in {"google.com", "www.google.com"} and parsed.path.lower().startswith("/amp/"):
        features.append("URL uses Google AMP as a redirect/wrapper")

    common_file_exts = {
        "html",
        "htm",
        "php",
        "aspx",
        "asp",
        "jsp",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "css",
        "js",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "zip",
    }
    path_text = urllib.parse.unquote(parsed.path)
    for path_domain_match in re.finditer(r"([a-z0-9-]+\.)+[a-z]{2,}", path_text, re.IGNORECASE):
        candidate = path_domain_match.group(0)
        tld = candidate.rsplit(".", 1)[-1].lower()
        next_char = path_text[path_domain_match.end() : path_domain_match.end() + 1]
        if tld in common_file_exts and next_char != "/":
            continue
        embedded_domain = normalize_domain(candidate)
        if embedded_domain and host and not domains_align(embedded_domain, host):
            features.append(f"URL path contains embedded domain {embedded_domain}")
            break

    displayed_url = None
    deceptive_display = False
    if link_text:
        text_urls = extract_urls_from_text(link_text)
        if text_urls:
            displayed_url = text_urls[0]
            displayed_host = url_host(displayed_url)
            if displayed_host and host and not domains_align(displayed_host, host):
                deceptive_display = True
                features.append(f"Link text displays {displayed_host} but href points to {host}")

    return {
        "url": url,
        "normalized_url": normalized or url,
        "defanged": defang(normalized or url),
        "source": source,
        "host": host,
        "registered_domain": registered_domain(host),
        "path": parsed.path,
        "query_keys": sorted(query.keys()),
        "link_text": link_text,
        "displayed_url": displayed_url,
        "deceptive_display": deceptive_display,
        "features": unique_list(features),
        "vt": None,
        "redirect_chain": [],
        "final_url": None,
    }


def extract_links(body, html_body):
    url_records = []

    for url in extract_urls_from_text(body):
        url_records.append(analyze_url(url, "body.text"))

    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for tag in soup.find_all(["a", "area"], href=True):
            url = clean_url(tag.get("href"))
            if url:
                url_records.append(analyze_url(url, "body.html.href", tag.get_text(" ", strip=True)))
        for tag in soup.find_all(["img", "script", "iframe"], src=True):
            url = clean_url(tag.get("src"))
            if url:
                url_records.append(analyze_url(url, f"body.html.{tag.name}.src"))
        for tag in soup.find_all("form", action=True):
            url = clean_url(tag.get("action"))
            if url:
                url_records.append(analyze_url(url, "body.html.form.action"))
        for tag in soup.find_all("meta"):
            content = tag.get("content", "")
            for url in extract_urls_from_text(content):
                url_records.append(analyze_url(url, "body.html.meta"))
        for url in extract_urls_from_text(soup.get_text(" ", strip=True)):
            url_records.append(analyze_url(url, "body.html.text"))

    deduped = {}
    for record in url_records:
        key = record["normalized_url"]
        if key not in deduped:
            deduped[key] = record
        else:
            deduped[key]["source"] = ",".join(unique_list(deduped[key]["source"].split(",") + [record["source"]]))
            deduped[key]["features"] = unique_list(deduped[key]["features"] + record["features"])
            if record.get("link_text") and not deduped[key].get("link_text"):
                deduped[key]["link_text"] = record["link_text"]
    return list(deduped.values())


def analyze_html_content(html_body):
    if not html_body:
        return {
            "javascript_present": False,
            "script_count": 0,
            "form_count": 0,
            "password_inputs": 0,
            "iframe_sources": [],
            "meta_refresh_urls": [],
            "hidden_element_count": 0,
        }

    soup = BeautifulSoup(html_body, "html.parser")
    script_count = len(soup.find_all("script"))
    forms = soup.find_all("form")
    password_inputs = len(soup.find_all("input", {"type": re.compile(r"password", re.IGNORECASE)}))
    iframe_sources = [clean_url(tag.get("src")) for tag in soup.find_all("iframe", src=True)]
    iframe_sources = unique_list([url for url in iframe_sources if url])
    meta_refresh_urls = []
    for tag in soup.find_all("meta"):
        if tag.get("http-equiv", "").lower() == "refresh":
            meta_refresh_urls.extend(extract_urls_from_text(tag.get("content", "")))

    hidden_elements = 0
    for tag in soup.find_all(True):
        style = tag.get("style", "")
        if tag.has_attr("hidden") or re.search(r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0", style, re.IGNORECASE):
            hidden_elements += 1

    return {
        "javascript_present": script_count > 0,
        "script_count": script_count,
        "form_count": len(forms),
        "password_inputs": password_inputs,
        "iframe_sources": iframe_sources,
        "meta_refresh_urls": unique_list(meta_refresh_urls),
        "hidden_element_count": hidden_elements,
    }


def scan_images_for_qrcodes(images_data):
    results = []
    if not IMAGE_SCANNING_AVAILABLE:
        return results
    for image in images_data:
        try:
            img = Image.open(BytesIO(image.get("data") or b""))
            decoded_qrs = qr_decode(img)
            urls = []
            if decoded_qrs:
                for qr in decoded_qrs:
                    value = qr.data.decode("utf-8", errors="ignore")
                    cleaned = clean_url(value)
                    if cleaned:
                        urls.append(cleaned)
            else:
                urls.extend(extract_urls_from_text(pytesseract.image_to_string(img)))

            for url in unique_list(urls):
                record = analyze_url(url, f"image.{image.get('filename')}.qr_or_ocr")
                results.append(record)
        except Exception as exc:
            print(f"{YELLOW}Warning: Could not process image '{image.get('filename')}'. Error: {exc}{RESET}")
    return results


def unshorten_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        chain = [r.url for r in response.history] + [response.url]
        return response.url, unique_list(chain)
    except Exception:
        return url, []


# -------------------------------
# ATTACHMENT ANALYSIS
# -------------------------------
def detect_file_type(data, filename=None, content_type=None):
    ext = os.path.splitext(filename or "")[1].lower()
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "zip_or_ooxml"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole_compound"
    if data.startswith(b"MZ"):
        return "pe_executable"
    if data.startswith(b"\x7fELF"):
        return "elf_executable"
    if data.startswith(b"Rar!"):
        return "rar_archive"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z_archive"
    if data.startswith(b"\x89PNG"):
        return "png_image"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg_image"
    return (mimetypes.guess_type(filename or "")[0] or content_type or ext or "unknown").lower()


def has_double_extension(filename):
    name = (filename or "").lower()
    parts = [part for part in name.split(".") if part]
    if len(parts) < 3:
        return False
    visible_doc_exts = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt"}
    risky_exts = {ext.lstrip(".") for ext in CONFIG["lists"]["risky_extensions"]}
    return parts[-2] in visible_doc_exts and parts[-1] in risky_exts


def analyze_pdf_static(data):
    lower = data.lower()
    indicators = []
    counts = {
        "javascript_markers": lower.count(b"/javascript") + lower.count(b"/js"),
        "open_action_markers": lower.count(b"/openaction"),
        "additional_action_markers": lower.count(b"/aa"),
        "launch_markers": lower.count(b"/launch"),
        "embedded_file_markers": lower.count(b"/embeddedfile"),
        "acroform_markers": lower.count(b"/acroform"),
        "uri_markers": lower.count(b"/uri"),
    }

    if counts["javascript_markers"]:
        indicators.append("PDF contains JavaScript markers")
    if counts["open_action_markers"]:
        indicators.append("PDF contains OpenAction markers")
    if counts["launch_markers"]:
        indicators.append("PDF contains Launch action markers")
    if counts["embedded_file_markers"]:
        indicators.append("PDF contains embedded file markers")
    if counts["acroform_markers"]:
        indicators.append("PDF contains AcroForm markers")

    uri_urls = []
    for match in re.findall(rb"/URI\s*\((.*?)\)", data, re.IGNORECASE | re.DOTALL):
        try:
            candidate = match.decode("utf-8", errors="ignore")
            cleaned = clean_url(candidate)
            if cleaned:
                uri_urls.append(cleaned)
        except Exception:
            continue

    return {
        "counts": counts,
        "indicators": indicators,
        "embedded_urls": unique_list(uri_urls + extract_urls_from_bytes(data)),
    }


def analyze_ooxml_zip(data):
    result = {
        "is_ooxml": False,
        "document_family": None,
        "file_count": 0,
        "macros_present": False,
        "external_relationships": [],
        "embedded_objects": [],
        "suspicious_archive_entries": [],
        "embedded_urls": [],
        "reference_urls_ignored": [],
        "indicators": [],
    }
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            names = archive.namelist()
            result["file_count"] = len(names)
            result["is_ooxml"] = "[Content_Types].xml" in names and any(
                name.startswith(("word/", "xl/", "ppt/")) for name in names
            )
            if any(name.startswith("word/") for name in names):
                result["document_family"] = "word"
            elif any(name.startswith("xl/") for name in names):
                result["document_family"] = "excel"
            elif any(name.startswith("ppt/") for name in names):
                result["document_family"] = "powerpoint"

            result["macros_present"] = any(name.lower().endswith("vbaproject.bin") for name in names)
            if result["macros_present"]:
                result["indicators"].append("OOXML document contains VBA macro project")

            risky_exts = tuple(CONFIG["lists"]["risky_extensions"])
            for name in names:
                lower = name.lower()
                if "/embeddings/" in lower or lower.endswith(".bin") and "oleobject" in lower:
                    result["embedded_objects"].append(name)
                if lower.endswith(risky_exts):
                    result["suspicious_archive_entries"].append(name)

            if result["embedded_objects"]:
                result["indicators"].append("OOXML document contains embedded objects")
            if result["suspicious_archive_entries"]:
                result["indicators"].append("Archive contains risky file extensions")

            rel_ns = {"rel": "http://schemas.openxmlformats.org/package/2006/relationships"}
            for name in names:
                if not name.lower().endswith(".rels"):
                    continue
                try:
                    xml_data = archive.read(name)
                    root = ElementTree.fromstring(xml_data)
                    for rel in root.findall("rel:Relationship", rel_ns):
                        target = rel.attrib.get("Target", "")
                        mode = rel.attrib.get("TargetMode", "")
                        rel_type = rel.attrib.get("Type", "")
                        if mode.lower() == "external" or clean_url(target):
                            cleaned = clean_url(target)
                            result["external_relationships"].append(
                                {
                                    "relationship_file": name,
                                    "type": rel_type,
                                    "target": target,
                                    "url": cleaned,
                                }
                            )
                            if cleaned:
                                result["embedded_urls"].append(cleaned)
                except Exception:
                    continue

            if result["external_relationships"]:
                result["indicators"].append("OOXML document contains external relationships")

            for name in names:
                if name.lower().endswith((".xml", ".rels", ".txt")):
                    try:
                        result["embedded_urls"].extend(extract_urls_from_bytes(archive.read(name)))
                    except Exception:
                        continue
    except zipfile.BadZipFile:
        return result
    result["embedded_urls"], result["reference_urls_ignored"] = filter_actionable_urls(result["embedded_urls"])
    return result


def analyze_ole_static(data, filename):
    result = {
        "oletools_available": OLETOOLS_AVAILABLE,
        "macros_present": None,
        "macro_indicators": [],
        "indicators": [],
    }
    if not OLETOOLS_AVAILABLE:
        result["indicators"].append("OLE Office document detected; macro scan unavailable because oletools is not installed")
        return result

    try:
        parser = VBA_Parser(filename or "attachment", data=data)
        macros_present = parser.detect_vba_macros()
        result["macros_present"] = macros_present
        if macros_present:
            result["indicators"].append("OLE document contains VBA macros")
            for indicator_type, keyword, description in parser.analyze_macros():
                result["macro_indicators"].append(
                    {
                        "type": indicator_type,
                        "keyword": keyword,
                        "description": description,
                    }
                )
        parser.close()
    except Exception as exc:
        result["indicators"].append(f"OLE macro scan failed: {exc}")
    return result


def extract_links_from_attachment_text(filename, data):
    if not ATTACHMENT_PARSING_AVAILABLE:
        return []

    filename_lower = (filename or "").lower()
    text = ""
    try:
        if filename_lower.endswith(".pdf") or data.startswith(b"%PDF"):
            with pdfplumber.open(BytesIO(data)) as pdf:
                text = "\n".join(page.extract_text() or "" for page in pdf.pages)
        elif filename_lower.endswith((".docx", ".docm")) or data.startswith(b"PK"):
            doc = docx.Document(BytesIO(data))
            text = "\n".join(para.text for para in doc.paragraphs)
    except Exception:
        return []
    return extract_urls_from_text(text)


def analyze_attachment(attachment):
    filename = attachment.get("filename") or "unknown"
    data = attachment.get("data") or b""
    content_type = attachment.get("content_type") or "application/octet-stream"
    detected_type = detect_file_type(data, filename, content_type)
    extension = os.path.splitext(filename)[1].lower()

    result = {
        "filename": filename,
        "content_type": content_type,
        "detected_type": detected_type,
        "size_bytes": len(data),
        "hashes": hashes_for_bytes(data),
        "extension": extension,
        "indicators": [],
        "embedded_urls": [],
        "reference_urls_ignored": [],
        "ooxml": None,
        "pdf": None,
        "ole": None,
        "vt": None,
    }

    if extension in CONFIG["lists"]["risky_extensions"]:
        result["indicators"].append(f"Risky attachment extension: {extension}")
    if has_double_extension(filename):
        result["indicators"].append("Attachment uses a double extension")
    if detected_type in {"pe_executable", "elf_executable"}:
        result["indicators"].append(f"Executable file detected: {detected_type}")
    guessed_content_type = mimetypes.guess_type(filename)[0]
    if guessed_content_type and content_type and guessed_content_type.split("/")[0] != content_type.split("/")[0]:
        result["indicators"].append(f"MIME type mismatch: header says {content_type}, filename suggests {guessed_content_type}")

    result["embedded_urls"].extend(extract_urls_from_bytes(data))
    result["embedded_urls"].extend(extract_links_from_attachment_text(filename, data))

    if detected_type == "pdf":
        pdf_result = analyze_pdf_static(data)
        result["pdf"] = pdf_result
        result["indicators"].extend(pdf_result["indicators"])
        result["embedded_urls"].extend(pdf_result["embedded_urls"])
    elif detected_type == "zip_or_ooxml":
        ooxml_result = analyze_ooxml_zip(data)
        result["ooxml"] = ooxml_result
        result["indicators"].extend(ooxml_result["indicators"])
        result["embedded_urls"].extend(ooxml_result["embedded_urls"])
        result["reference_urls_ignored"].extend(ooxml_result.get("reference_urls_ignored", []))
    elif detected_type == "ole_compound":
        ole_result = analyze_ole_static(data, filename)
        result["ole"] = ole_result
        result["indicators"].extend(ole_result["indicators"])

    actionable_urls, ignored_urls = filter_actionable_urls(result["embedded_urls"])
    result["embedded_urls"] = actionable_urls
    result["reference_urls_ignored"] = unique_list(result["reference_urls_ignored"] + ignored_urls)
    if result["embedded_urls"]:
        result["indicators"].append("Attachment contains embedded external URL(s)")
    result["indicators"] = unique_list(result["indicators"])
    return result


# -------------------------------
# OBSERVABLES
# -------------------------------
def add_observable(observables, index, observable_type, value, source, role=None, metadata=None):
    if not value:
        return None

    if observable_type == "email":
        normalized = normalize_email_address(value)
    elif observable_type == "domain":
        normalized = normalize_domain(value)
    elif observable_type == "ip":
        normalized = normalize_ip(value)
    elif observable_type == "url":
        normalized = normalize_url(value)
    elif observable_type in {"md5", "sha1", "sha256"}:
        normalized = str(value).lower()
    else:
        normalized = str(value).strip()

    if not normalized:
        return None

    key = (observable_type, normalized)
    if key not in index:
        observable = {
            "type": observable_type,
            "value": normalized,
            "defanged": defang(normalized) if observable_type in {"domain", "url", "email", "ip"} else normalized,
            "sources": [],
            "roles": [],
            "metadata": {},
            "vt": None,
        }
        if observable_type == "domain":
            observable["registered_domain"] = registered_domain(normalized)
        if observable_type == "ip":
            observable["is_public"] = is_public_ip(normalized)
        index[key] = observable
        observables.append(observable)
    else:
        observable = index[key]

    if source and source not in observable["sources"]:
        observable["sources"].append(source)
    if role and role not in observable["roles"]:
        observable["roles"].append(role)
    if metadata:
        for key_name, meta_value in metadata.items():
            if key_name not in observable["metadata"]:
                observable["metadata"][key_name] = meta_value
            elif observable["metadata"][key_name] != meta_value:
                existing = observable["metadata"][key_name]
                if not isinstance(existing, list):
                    existing = [existing]
                observable["metadata"][key_name] = unique_list(existing + [meta_value])
    return observable


def build_observables(header_findings, url_records, attachment_results):
    observables = []
    index = {}

    for header_name in ("From", "Return-Path", "Reply-To"):
        box = header_findings.get(header_name)
        if box:
            add_observable(observables, index, "email", box["address"], f"header.{header_name}", header_name.lower())
            add_observable(observables, index, "domain", box["domain"], f"header.{header_name}", f"{header_name.lower()}_domain")

    for header_name in ("To", "Cc"):
        for box in header_findings.get(header_name, []):
            add_observable(observables, index, "email", box["address"], f"header.{header_name}", header_name.lower())
            add_observable(observables, index, "domain", box["domain"], f"header.{header_name}", f"{header_name.lower()}_domain")

    for domain in header_findings.get("SPF MailFrom Domains", []):
        add_observable(observables, index, "domain", domain, "auth.smtp.mailfrom", "spf_mailfrom")
    for domain in header_findings.get("Header From Domains", []):
        add_observable(observables, index, "domain", domain, "auth.header.from", "header_from")
    for domain in header_findings.get("DKIM Domains", []):
        add_observable(observables, index, "domain", domain, "auth.header.d", "dkim_domain")
    for email_address in header_findings.get("Display Name Claimed Emails", []):
        add_observable(observables, index, "email", email_address, "header.From.display_name", "display_name_claim")
    for domain in header_findings.get("Display Name Claimed Domains", []):
        add_observable(observables, index, "domain", domain, "header.From.display_name", "display_name_claim_domain")
    for ip in header_findings.get("Sender IPs", []):
        add_observable(observables, index, "ip", ip, "auth_or_received.sender_ip", "sender_ip")

    for hop in header_findings.get("Received Path", []):
        for ip in hop.get("public_ips", []):
            add_observable(
                observables,
                index,
                "ip",
                ip,
                f"received.hop_{hop.get('hop')}",
                "received_public_ip",
                {"from": hop.get("from"), "by": hop.get("by")},
            )

    for record in url_records:
        add_observable(
            observables,
            index,
            "url",
            record["normalized_url"],
            record["source"],
            "embedded_url",
            {"host": record.get("host"), "features": record.get("features")},
        )
        if record.get("host"):
            add_observable(observables, index, "domain", record["host"], record["source"], "url_host")

    for attachment in attachment_results:
        hashes = attachment.get("hashes", {})
        for hash_type in ("md5", "sha1", "sha256"):
            add_observable(
                observables,
                index,
                hash_type,
                hashes.get(hash_type),
                f"attachment.{attachment.get('filename')}",
                "attachment_hash",
            )
        for embedded_url in attachment.get("embedded_urls", []):
            record = analyze_url(embedded_url, f"attachment.{attachment.get('filename')}.embedded_url")
            add_observable(observables, index, "url", record["normalized_url"], record["source"], "attachment_url")
            if record.get("host"):
                add_observable(observables, index, "domain", record["host"], record["source"], "attachment_url_host")

    return observables


# -------------------------------
# VIRUSTOTAL API FUNCTIONS
# -------------------------------
def vt_fetch(path):
    if not VT_AVAILABLE:
        return {"status": "skipped", "reason": "VT_API_KEY is not set"}

    headers = {"x-apikey": API_KEY, "accept": "application/json"}
    url = f"https://www.virustotal.com/api/v3/{path.lstrip('/')}"
    try:
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code == 429:
            return {"status": "rate_limited", "http_status": 429, "reason": "VirusTotal API rate limit exceeded"}
        if response.status_code == 404:
            return {"status": "not_found", "http_status": 404}
        if response.status_code != 200:
            return {"status": "error", "http_status": response.status_code, "reason": response.text[:300]}
        return {"status": "ok", "http_status": 200, "json": response.json()}
    except requests.exceptions.RequestException as exc:
        return {"status": "error", "reason": f"Request error: {exc}"}


def vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def summarize_vt_response(response, object_type):
    if response.get("status") != "ok":
        return response

    data = response.get("json", {}).get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}
    engine_hits = []
    for engine, result in results.items():
        if result.get("category") in {"malicious", "suspicious"}:
            engine_hits.append(
                {
                    "engine": engine,
                    "category": result.get("category"),
                    "result": result.get("result"),
                }
            )

    summary = {
        "status": "ok",
        "object_type": object_type,
        "id": data.get("id"),
        "last_analysis_stats": stats,
        "detections": int(stats.get("malicious", 0) or 0) + int(stats.get("suspicious", 0) or 0),
        "total_engines": sum(int(v or 0) for v in stats.values()),
        "reputation": attrs.get("reputation"),
        "tags": attrs.get("tags", [])[:20] if isinstance(attrs.get("tags"), list) else attrs.get("tags"),
        "categories": unique_list(list((attrs.get("categories") or {}).values()))[:20],
        "engine_hits": engine_hits[:30],
        "first_submission_date": timestamp_to_iso(attrs.get("first_submission_date")),
        "last_submission_date": timestamp_to_iso(attrs.get("last_submission_date")),
        "last_analysis_date": timestamp_to_iso(attrs.get("last_analysis_date")),
    }

    if object_type == "url":
        summary.update(
            {
                "last_final_url": attrs.get("last_final_url"),
                "redirection_chain": attrs.get("redirection_chain", [])[:20],
                "last_http_response_code": attrs.get("last_http_response_code"),
                "title": attrs.get("title"),
                "targeted_brand": attrs.get("targeted_brand"),
                "outgoing_links": attrs.get("outgoing_links", [])[:20],
            }
        )
    elif object_type == "domain":
        dns_records = attrs.get("last_dns_records", []) or []
        summary.update(
            {
                "registrar": attrs.get("registrar"),
                "creation_date": timestamp_to_iso(attrs.get("creation_date")),
                "last_dns_records": [
                    {
                        "type": record.get("type"),
                        "value": record.get("value"),
                    }
                    for record in dns_records[:20]
                ],
                "popularity_ranks": attrs.get("popularity_ranks", {}),
            }
        )
    elif object_type == "ip":
        summary.update(
            {
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "country": attrs.get("country"),
                "network": attrs.get("network"),
            }
        )
    elif object_type == "file":
        threat = attrs.get("popular_threat_classification") or {}
        summary.update(
            {
                "md5": attrs.get("md5"),
                "sha1": attrs.get("sha1"),
                "sha256": attrs.get("sha256"),
                "meaningful_name": attrs.get("meaningful_name"),
                "type_description": attrs.get("type_description"),
                "magic": attrs.get("magic"),
                "type_tag": attrs.get("type_tag"),
                "names": attrs.get("names", [])[:20],
                "popular_threat_classification": threat,
                "crowdsourced_yara_results": attrs.get("crowdsourced_yara_results", [])[:10],
            }
        )
    return summary


def scan_domain(domain):
    return summarize_vt_response(vt_fetch(f"domains/{urllib.parse.quote(domain, safe='')}"), "domain")


def scan_ip(ip_value):
    return summarize_vt_response(vt_fetch(f"ip_addresses/{urllib.parse.quote(ip_value, safe='')}"), "ip")


def scan_url(url):
    return summarize_vt_response(vt_fetch(f"urls/{vt_url_id(url)}"), "url")


def scan_file_hash(file_hash):
    return summarize_vt_response(vt_fetch(f"files/{file_hash}"), "file")


def vt_detection_count(vt_result):
    if not vt_result or vt_result.get("status") != "ok":
        return 0
    return int(vt_result.get("detections") or 0)


def vt_summary_text(vt_result):
    if not vt_result:
        return "not scanned"
    status = vt_result.get("status")
    if status == "ok":
        return f"{vt_result.get('detections', 0)} of {vt_result.get('total_engines', 0)} engines flagged"
    if status == "skipped":
        return f"skipped: {vt_result.get('reason')}"
    if status == "not_found":
        return "not found in VirusTotal"
    if status == "rate_limited":
        return "API rate limit exceeded"
    return f"{status}: {vt_result.get('reason') or vt_result.get('http_status')}"


def colorize_vt(vt_result):
    text = vt_summary_text(vt_result)
    if vt_detection_count(vt_result) > 0:
        return f"{RED}{CROSS} {text}{RESET}"
    if vt_result and vt_result.get("status") == "ok":
        return f"{GREEN}{CHECK} {text}{RESET}"
    return f"{YELLOW}{INFO} {text}{RESET}"


def enrich_with_virustotal(observables, url_records, attachment_results, delay_seconds, max_items, no_vt):
    if no_vt or not VT_AVAILABLE:
        skipped = {
            "status": "skipped",
            "reason": "disabled by --no-vt" if no_vt else "VT_API_KEY is not set",
        }
        for observable in observables:
            if observable["type"] in {"domain", "ip", "url", "sha256"}:
                observable["vt"] = skipped
        for url_record in url_records:
            url_record["vt"] = skipped
        for attachment in attachment_results:
            attachment["vt"] = skipped
        return {"scanned": 0, "skipped_reason": skipped["reason"]}

    scanned = 0

    domain_map = {obs["value"]: obs for obs in observables if obs["type"] == "domain"}
    ip_map = {obs["value"]: obs for obs in observables if obs["type"] == "ip" and obs.get("is_public")}
    url_map = {record["normalized_url"]: record for record in url_records}
    sha_map = {attachment["hashes"]["sha256"]: attachment for attachment in attachment_results}

    queues = [
        ("domain", sorted(domain_map.items()), scan_domain),
        ("ip", sorted(ip_map.items()), scan_ip),
        ("url", sorted(url_map.items()), scan_url),
        ("file", sorted(sha_map.items()), scan_file_hash),
    ]

    for object_type, items, scanner in queues:
        if not items:
            continue
        print(f"\n{CYAN}{BOLD}========== VIRUSTOTAL {object_type.upper()} SCANNING =========={RESET}")
        for value, target in items:
            if scanned >= max_items:
                skipped = {"status": "skipped", "reason": f"max VT item limit reached ({max_items})"}
                if object_type == "file":
                    target["vt"] = skipped
                else:
                    target["vt"] = skipped
                print(f"{YELLOW}{INFO} Skipping remaining VT items: max limit reached.{RESET}")
                return {"scanned": scanned, "skipped_reason": skipped["reason"]}

            result = scanner(value)
            if object_type == "file":
                target["vt"] = result
                display_value = target.get("filename", value)
            else:
                target["vt"] = result
                display_value = value
                if object_type == "url":
                    target["final_url"] = result.get("last_final_url") if result.get("status") == "ok" else None
                    target["redirect_chain"] = result.get("redirection_chain", []) if result.get("status") == "ok" else []

            print(f"{BOLD}{BLUE}{object_type.capitalize()}:{RESET} {MAGENTA}{display_value}{RESET} -> {colorize_vt(result)}")
            scanned += 1
            if delay_seconds > 0 and scanned < max_items:
                time.sleep(delay_seconds)

    # Copy URL VT results onto matching URL observables.
    url_vt_by_value = {record["normalized_url"]: record.get("vt") for record in url_records}
    file_vt_by_sha = {attachment["hashes"]["sha256"]: attachment.get("vt") for attachment in attachment_results}
    for observable in observables:
        if observable["type"] == "url" and observable["value"] in url_vt_by_value:
            observable["vt"] = url_vt_by_value[observable["value"]]
        elif observable["type"] == "sha256" and observable["value"] in file_vt_by_sha:
            observable["vt"] = file_vt_by_sha[observable["value"]]

    return {"scanned": scanned, "skipped_reason": None}


# -------------------------------
# SCORING
# -------------------------------
def generate_score_and_feedback(data):
    score = 0
    feedback_items = []
    w = CONFIG["weights"]
    header = data["header_findings"]

    if header.get("Return-Path Mismatch"):
        score += w["mismatch_return_path"]
        feedback_items.append(
            f"{RED}{CROSS} Return-Path Mismatch:{RESET} {header.get('Return-Path Address')} differs from {header.get('From Address')}."
        )

    if header.get("Reply-To Mismatch"):
        score += w["mismatch_reply_to"]
        feedback_items.append(
            f"{RED}{CROSS} Reply-To Mismatch:{RESET} Replies go to {header.get('Reply-To Address')} instead of {header.get('From Address')}."
        )

    dmarc_res = header.get("DMARC Result")
    if dmarc_res == "fail":
        score += w["dmarc_fail"]
        feedback_items.append(f"{RED}{CROSS} DMARC Failure:{RESET} Header From domain failed DMARC validation.")
    elif dmarc_res in {"none", "not found", "neutral"}:
        score += w["dmarc_weak_or_missing"]
        feedback_items.append(
            f"{YELLOW}{INFO} DMARC Weak/Missing:{RESET} DMARC result is '{dmarc_res}', so enforcement/alignment is not confirmed."
        )

    spf_res = header.get("SPF Result")
    if spf_res not in {"pass", "not found", "neutral", "none"}:
        score += w["spf_fail"]
        feedback_items.append(f"{RED}{CROSS} SPF Failure:{RESET} SPF result is '{spf_res}'.")
    elif spf_res == "not found":
        score += w["spf_not_found"]
        feedback_items.append(f"{YELLOW}{INFO} SPF Missing:{RESET} No SPF result was found in Authentication-Results.")

    dkim_res = header.get("DKIM Result")
    if dkim_res not in {"pass", "not found", "neutral", "none"}:
        score += w["dkim_fail"]
        feedback_items.append(f"{RED}{CROSS} DKIM Failure:{RESET} DKIM result is '{dkim_res}'.")
    elif dkim_res == "not found":
        score += w["dkim_not_found"]
        feedback_items.append(f"{YELLOW}{INFO} DKIM Missing:{RESET} No DKIM result was found in Authentication-Results.")

    if header.get("SPF Aligned") is False and spf_res == "pass":
        score += w["auth_alignment_mismatch"]
        feedback_items.append(
            f"{RED}{CROSS} SPF Alignment Mismatch:{RESET} SPF passed for {header.get('SPF MailFrom Domains')} but Header From is {header.get('Header From Domains') or (header.get('From') or {}).get('domain')}."
        )

    if header.get("DKIM Aligned") is False and dkim_res == "pass":
        score += w["auth_alignment_mismatch"]
        feedback_items.append(
            f"{RED}{CROSS} DKIM Alignment Mismatch:{RESET} DKIM domain(s) {header.get('DKIM Domains')} do not align with Header From."
        )

    if header.get("CompAuth Result") and header.get("CompAuth Result") not in {"pass", "softpass"}:
        score += w["compauth_fail"]
        feedback_items.append(
            f"{RED}{CROSS} Microsoft Composite Auth:{RESET} compauth={header.get('CompAuth Result')} reason={header.get('CompAuth Reason')}."
        )

    if header.get("Display Name Domain Mismatch"):
        score += w["display_name_domain_mismatch"]
        feedback_items.append(
            f"{RED}{CROSS} Display Name Impersonation:{RESET} Display name claims {header.get('Display Name Claimed Domains')} but actual From domain is {(header.get('From') or {}).get('domain')}."
        )

    if header.get("Display Name Brand Mismatch"):
        score += w["brand_impersonation"]
        feedback_items.append(
            f"{RED}{CROSS} Brand Display Name Mismatch:{RESET} Display name mentions {header.get('Display Name Brand Mentions')} but From domain is {(header.get('From') or {}).get('domain')}."
        )

    if data["spoof_findings"].get("is_homograph_attack"):
        score += w["homograph_attack"]
        feedback_items.append(f"{RED}{CROSS} Homograph/Punycode Risk:{RESET} Sender domain contains look-alike encoding.")

    if data["domain_age"] is not None and data["domain_age"] < CONFIG["settings"]["domain_age_threshold_days"]:
        score += w["recent_domain"]
        feedback_items.append(
            f"{RED}{CROSS} Recently Created Domain:{RESET} Sender domain is only {data['domain_age']} days old."
        )

    for observable in data["observables"]:
        detections = vt_detection_count(observable.get("vt"))
        if detections <= 0:
            continue
        if observable["type"] == "domain":
            score += w["malicious_domain"]
            feedback_items.append(
                f"{RED}{CROSS} Malicious Domain:{RESET} {observable['value']} -> {vt_summary_text(observable.get('vt'))}."
            )
        elif observable["type"] == "ip":
            score += w["malicious_ip"]
            feedback_items.append(
                f"{RED}{CROSS} Malicious IP:{RESET} {observable['value']} -> {vt_summary_text(observable.get('vt'))}."
            )
        elif observable["type"] == "url":
            score += w["malicious_link"]
            feedback_items.append(
                f"{RED}{CROSS} Malicious URL:{RESET} {defang(observable['value'])} -> {vt_summary_text(observable.get('vt'))}."
            )

    for url_record in data["url_results"]:
        if url_record.get("deceptive_display"):
            score += w["deceptive_link"]
            feedback_items.append(
                f"{RED}{CROSS} Deceptive Link:{RESET} displayed URL does not match href for {defang(url_record['normalized_url'])}."
            )
        if url_record.get("features"):
            score += w["suspicious_url_feature"]
            feedback_items.append(
                f"{YELLOW}{INFO} Suspicious URL Feature:{RESET} {defang(url_record['normalized_url'])}: {', '.join(url_record['features'])}."
            )
        if any(service in (url_record.get("host") or "") for service in CONFIG["lists"]["abused_legit_services"]):
            score += w["abused_service_link"]
            feedback_items.append(
                f"{YELLOW}{INFO} Abused Legit Service:{RESET} Link uses {url_record.get('host')}, a service often abused for phishing delivery."
            )

    for attachment in data["attachment_results"]:
        detections = vt_detection_count(attachment.get("vt"))
        sha256 = attachment.get("hashes", {}).get("sha256")
        if detections > 0:
            score = max(score, w["malicious_attachment"])
            feedback_items.append(
                f"{RED}{CROSS} Malicious Attachment:{RESET} {attachment['filename']} sha256={sha256} -> {vt_summary_text(attachment.get('vt'))}."
            )
        elif attachment.get("indicators"):
            score += w["suspicious_attachment"]
            feedback_items.append(
                f"{RED}{CROSS} Suspicious Attachment:{RESET} {attachment['filename']} sha256={sha256}; indicators: {', '.join(attachment['indicators'])}."
            )

    content = data["content_findings"]
    if content.get("javascript_present"):
        score += w["javascript_present"]
        feedback_items.append(
            f"{YELLOW}{INFO} HTML Script Content:{RESET} Email contains {content.get('script_count')} script tag(s)."
        )
    if content.get("password_inputs") or content.get("form_count"):
        score += w["credential_form"]
        feedback_items.append(
            f"{RED}{CROSS} Credential Form Indicators:{RESET} HTML contains {content.get('form_count')} form(s) and {content.get('password_inputs')} password input(s)."
        )

    full_text = data["full_body"].lower()
    if any(keyword in full_text for keyword in CONFIG["lists"]["high_risk_keywords"]):
        score += w["high_risk_keywords"]
        feedback_items.append(f"{RED}{CROSS} High-Risk Keywords:{RESET} Found terms often used in financial scams.")

    if re.search(r"\burgent\b|\bverify\b|\bpassword\b|\baccount\b|\bconfirm\b|\bsuspended\b|\binvoice\b", full_text):
        score += w["urgent_keywords"]
        feedback_items.append(f"{YELLOW}{INFO} Pressure Language:{RESET} Body contains urgency/account-verification wording.")
        if any(brand in full_text for brand in CONFIG["lists"]["impersonated_brands"]):
            score += w["impersonation_keywords"]
            feedback_items.append(f"{RED}{CROSS} Brand Impersonation Context:{RESET} Pressure wording appears with known brand names.")

    if all(header.get(f"{name} Result") == "pass" for name in ("SPF", "DKIM", "DMARC")):
        feedback_items.append(f"{GREEN}{CHECK} Sender Identity Verified:{RESET} SPF, DKIM, and DMARC passed.")

    if not feedback_items:
        feedback_items.append(f"{GREEN}{CHECK} No major risk factors were detected by the configured checks.{RESET}")

    return min(score, 10), unique_list(feedback_items)


# -------------------------------
# OUTPUT
# -------------------------------
def print_auth_result(name, value):
    print(f"{BOLD}{BLUE}{name} Result:{RESET} ", end="")
    if value == "pass":
        print(f"{GREEN}{CHECK} Pass{RESET}")
    elif value in {"not found", "none", "neutral"}:
        print(f"{YELLOW}{INFO} {value}{RESET}")
    else:
        print(f"{RED}{CROSS} {value}{RESET}")


def print_header_analysis(header_findings, spoof_findings, domain_age):
    print(f"\n{CYAN}{BOLD}========== HEADER ANALYSIS =========={RESET}")
    from_box = header_findings.get("From") or {}
    print(f"{BOLD}{BLUE}Display Name:{RESET} {from_box.get('display_name') or 'Not Found'}")
    print(f"{BOLD}{BLUE}From Address:{RESET} {header_findings.get('From Address') or 'Not Found'}")
    print(f"{BOLD}{BLUE}Return-Path:{RESET} {header_findings.get('Return-Path Address') or 'Not Found'}")
    print(f"{BOLD}{BLUE}Reply-To:{RESET} {header_findings.get('Reply-To Address') or 'Not Found'}")

    if header_findings.get("Return-Path Mismatch") is True:
        print(f"{RED}{CROSS} Return-Path mismatch detected.{RESET}")
    elif header_findings.get("Return-Path Mismatch") is False:
        print(f"{GREEN}{CHECK} Return-Path matches From address exactly.{RESET}")
    else:
        print(f"{YELLOW}{INFO} Return-Path not available for comparison.{RESET}")

    if header_findings.get("Reply-To Mismatch") is True:
        print(f"{RED}{CROSS} Reply-To mismatch detected.{RESET}")

    for auth_name in ("SPF", "DKIM", "DMARC"):
        print_auth_result(auth_name, header_findings.get(f"{auth_name} Result"))

    print(f"{BOLD}{BLUE}SPF MailFrom Domains:{RESET} {header_findings.get('SPF MailFrom Domains') or 'None'}")
    print(f"{BOLD}{BLUE}DKIM Domains:{RESET} {header_findings.get('DKIM Domains') or 'None'}")
    if header_findings.get("Display Name Claimed Domains"):
        print(f"{BOLD}{BLUE}Display Name Claimed Domains:{RESET} {header_findings.get('Display Name Claimed Domains')}")
        if header_findings.get("Display Name Domain Mismatch"):
            print(f"{RED}{CROSS} Display name claims a different domain than the actual From address.{RESET}")
    if header_findings.get("Display Name Brand Mentions"):
        print(f"{BOLD}{BLUE}Display Name Brand Mentions:{RESET} {header_findings.get('Display Name Brand Mentions')}")
        if header_findings.get("Display Name Brand Mismatch"):
            print(f"{RED}{CROSS} Display name uses a brand that does not match the actual From domain.{RESET}")
    print(f"{BOLD}{BLUE}SPF Aligned:{RESET} {header_findings.get('SPF Aligned')}")
    print(f"{BOLD}{BLUE}DKIM Aligned:{RESET} {header_findings.get('DKIM Aligned')}")
    if header_findings.get("CompAuth Result"):
        print(
            f"{BOLD}{BLUE}Microsoft CompAuth:{RESET} {header_findings.get('CompAuth Result')} "
            f"reason={header_findings.get('CompAuth Reason')}"
        )

    sender_ips = header_findings.get("Sender IPs") or []
    print(f"{BOLD}{BLUE}Sender/Public Relay IPs:{RESET} {', '.join(sender_ips) if sender_ips else 'None'}")

    if domain_age is not None:
        color = RED if domain_age < CONFIG["settings"]["domain_age_threshold_days"] else GREEN
        print(f"{BOLD}{BLUE}Sender Domain Age:{RESET} {color}{domain_age} days{RESET}")
    elif not WHOIS_AVAILABLE and header_findings.get("From"):
        print(f"{YELLOW}{INFO} Domain age skipped: python-whois is not installed.{RESET}")

    if spoof_findings.get("is_homograph_attack"):
        print(f"{RED}{CROSS} Homograph/Punycode risk detected.{RESET}")
    if spoof_findings.get("punycode_version"):
        print(f"{YELLOW}{INFO} Punycode domain: {spoof_findings['punycode_version']}{RESET}")

    ms_fields = header_findings.get("Microsoft Security Headers", {}).get("fields", {})
    interesting_ms = {key: ms_fields.get(key) for key in ("CIP", "CTRY", "SCL", "BCL", "PCL", "CAT", "SFTY", "SFV", "IPV", "PTR") if ms_fields.get(key)}
    if interesting_ms:
        print(f"{CYAN}{BOLD}Microsoft Filter Fields:{RESET}")
        for key, value in interesting_ms.items():
            print(f"{YELLOW}- {key}: {', '.join(value)}{RESET}")

    print(f"{CYAN}{BOLD}Received Path:{RESET}")
    for hop in header_findings.get("Received Path", []):
        ips = ", ".join(hop.get("public_ips") or hop.get("ips") or [])
        print(f"{YELLOW}- hop {hop['hop']}: from {hop.get('from')} by {hop.get('by')} ips=[{ips}]{RESET}")


def print_iocs(observables, url_records, attachment_results):
    print(f"\n{CYAN}{BOLD}========== TECHNICAL IOCs =========={RESET}")
    grouped = defaultdict(list)
    for observable in observables:
        grouped[observable["type"]].append(observable)

    for observable_type in ("email", "domain", "ip", "url", "sha256"):
        items = grouped.get(observable_type, [])
        if not items:
            continue
        print(f"{BOLD}{BLUE}{observable_type.upper()}:{RESET}")
        for item in items[:30]:
            source = ",".join(item.get("sources", []))
            vt_text = ""
            if item.get("vt"):
                vt_text = f" | VT: {vt_summary_text(item['vt'])}"
            print(f"{MAGENTA}- {item.get('defanged') or item['value']}{RESET} | source: {source}{vt_text}")
        if len(items) > 30:
            print(f"{YELLOW}{INFO} ... {len(items) - 30} more {observable_type} observable(s) in JSON report.{RESET}")

    if url_records:
        print(f"\n{CYAN}{BOLD}URL DETAILS:{RESET}")
        for record in url_records[:20]:
            print(f"{MAGENTA}- {record['defanged']}{RESET}")
            print(f"  source={record['source']} host={record.get('host')} VT={vt_summary_text(record.get('vt'))}")
            if record.get("features"):
                print(f"  features={'; '.join(record['features'])}")
            if record.get("final_url") and record.get("final_url") != record["normalized_url"]:
                print(f"  final={defang(record['final_url'])}")

    if attachment_results:
        print(f"\n{CYAN}{BOLD}ATTACHMENT DETAILS:{RESET}")
        for attachment in attachment_results:
            print(f"{MAGENTA}- {attachment['filename']}{RESET}")
            print(
                f"  type={attachment['detected_type']} size={attachment['size_bytes']} "
                f"sha256={attachment['hashes']['sha256']} VT={vt_summary_text(attachment.get('vt'))}"
            )
            if attachment.get("indicators"):
                print(f"  indicators={'; '.join(attachment['indicators'])}")
            if attachment.get("embedded_urls"):
                print(f"  embedded_urls={', '.join(defang(url) for url in attachment['embedded_urls'][:5])}")
            if attachment.get("reference_urls_ignored"):
                print(f"  ignored_reference_urls={len(attachment['reference_urls_ignored'])}")


def build_report(args, verdict, score, feedback_items, analysis_data):
    return {
        "file": args.eml_file,
        "analysis_time_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": strip_ansi(verdict),
        "score": score,
        "feedback": [strip_ansi(item) for item in feedback_items],
        "summary": {
            "observable_count": len(analysis_data["observables"]),
            "url_count": len(analysis_data["url_results"]),
            "attachment_count": len(analysis_data["attachment_results"]),
            "sender_ips": analysis_data["header_findings"].get("Sender IPs", []),
        },
        "details": {
            "header_findings": analysis_data["header_findings"],
            "spoof_findings": analysis_data["spoof_findings"],
            "domain_age_days": analysis_data["domain_age"],
            "content_findings": analysis_data["content_findings"],
            "observables": analysis_data["observables"],
            "url_results": analysis_data["url_results"],
            "attachment_results": analysis_data["attachment_results"],
            "virustotal": analysis_data["virustotal"],
        },
    }


# -------------------------------
# MAIN PROGRAM
# -------------------------------
def main():
    parser = argparse.ArgumentParser(description="Enhanced Phishing Email Analyzer with IOC reporting")
    parser.add_argument("eml_file", help="Path to the .eml file to scan")
    parser.add_argument("--report", help="Path to save a detailed JSON analysis report", default=None)
    parser.add_argument("--no-vt", action="store_true", help="Skip VirusTotal enrichment even if VT_API_KEY is set")
    parser.add_argument(
        "--resolve-redirects",
        action="store_true",
        help="Actively request URLs to resolve redirects. Disabled by default to avoid contacting attacker infrastructure.",
    )
    parser.add_argument(
        "--vt-delay",
        type=float,
        default=CONFIG["settings"]["default_vt_delay_seconds"],
        help="Delay between VirusTotal requests in seconds",
    )
    parser.add_argument(
        "--max-vt-items",
        type=int,
        default=CONFIG["settings"]["default_max_vt_items"],
        help="Maximum number of VirusTotal items to enrich",
    )
    args = parser.parse_args()

    try:
        msg, header_text, body, html_body, attachments, images = parse_eml_file(args.eml_file)
    except FileNotFoundError:
        print(f"{RED}Error: File not found: {args.eml_file}{RESET}")
        return

    header_findings = analyze_header(msg)
    from_addr = header_findings.get("From Address")
    sender_domain = from_addr.split("@")[-1] if from_addr else None
    spoof_findings = analyze_domain_for_spoofing(sender_domain)
    domain_age = check_domain_age(sender_domain) if sender_domain else None

    print_header_analysis(header_findings, spoof_findings, domain_age)

    url_records = extract_links(body, html_body)
    url_records.extend(scan_images_for_qrcodes(images))

    attachment_results = []
    if attachments:
        print(f"\n{CYAN}{BOLD}========== STATIC ATTACHMENT ANALYSIS =========={RESET}")
        for attachment in attachments:
            result = analyze_attachment(attachment)
            attachment_results.append(result)
            print(
                f"{BOLD}{BLUE}Attachment:{RESET} {MAGENTA}{result['filename']}{RESET} "
                f"type={result['detected_type']} sha256={result['hashes']['sha256']}"
            )
            if result["indicators"]:
                print(f"{YELLOW}{INFO} Indicators: {'; '.join(result['indicators'])}{RESET}")

    for attachment in attachment_results:
        for embedded_url in attachment.get("embedded_urls", []):
            url_records.append(analyze_url(embedded_url, f"attachment.{attachment['filename']}.embedded_url"))

    # Dedupe URL records after attachment and image extraction.
    deduped_urls = {}
    for record in url_records:
        key = record["normalized_url"]
        if key not in deduped_urls:
            deduped_urls[key] = record
        else:
            deduped_urls[key]["source"] = ",".join(unique_list(deduped_urls[key]["source"].split(",") + [record["source"]]))
            deduped_urls[key]["features"] = unique_list(deduped_urls[key]["features"] + record["features"])
    url_records = list(deduped_urls.values())

    if url_records:
        print(f"\n{CYAN}{BOLD}========== URL EXTRACTION =========={RESET}")
        for record in url_records:
            if args.resolve_redirects:
                final_url, redirect_chain = unshorten_url(record["normalized_url"])
                record["final_url"] = final_url
                record["redirect_chain"] = redirect_chain
                if final_url and final_url != record["normalized_url"]:
                    final_record = analyze_url(final_url, f"{record['source']}.redirect_final")
                    record["features"] = unique_list(record["features"] + final_record["features"])
            print(f"{BOLD}{BLUE}URL:{RESET} {MAGENTA}{record['defanged']}{RESET} host={record.get('host')}")
            if record["features"]:
                print(f"{YELLOW}{INFO} Features: {'; '.join(record['features'])}{RESET}")

    content_findings = analyze_html_content(html_body)
    observables = build_observables(header_findings, url_records, attachment_results)
    vt_summary = enrich_with_virustotal(
        observables,
        url_records,
        attachment_results,
        delay_seconds=max(args.vt_delay, 0),
        max_items=max(args.max_vt_items, 0),
        no_vt=args.no_vt,
    )

    analysis_data = {
        "header_text": header_text,
        "header_findings": header_findings,
        "spoof_findings": spoof_findings,
        "url_results": url_records,
        "attachment_results": attachment_results,
        "observables": observables,
        "full_body": body + "\n" + html_body,
        "domain_age": domain_age,
        "content_findings": content_findings,
        "virustotal": vt_summary,
    }

    print_iocs(observables, url_records, attachment_results)
    score, feedback_items = generate_score_and_feedback(analysis_data)

    if score >= 7:
        verdict, score_color = f"{RED}{BOLD}UNSAFE{RESET}", RED
    elif score >= 4:
        verdict, score_color = f"{YELLOW}{BOLD}CAUTIOUS{RESET}", YELLOW
    else:
        verdict, score_color = f"{GREEN}{BOLD}SAFE{RESET}", GREEN

    print(f"\n{CYAN}{BOLD}========== FINAL VERDICT =========={RESET}")
    print(f"{BOLD}{BLUE}Phishing Score:{RESET} {score_color}{BOLD}{score}/10{RESET}")
    print(f"{BOLD}{BLUE}Verdict:{RESET} {verdict}")

    print(f"\n{CYAN}{BOLD}========== DETAILED FEEDBACK =========={RESET}")
    for item in feedback_items:
        print(item)

    if args.report:
        report_data = build_report(args, verdict, score, feedback_items, analysis_data)
        try:
            with open(args.report, "w", encoding="utf-8") as file:
                json.dump(report_data, file, indent=4, ensure_ascii=True)
            print(f"\n{CYAN}Detailed IOC report saved to {args.report}{RESET}")
        except Exception as exc:
            print(f"\n{RED}Error saving report: {exc}{RESET}")


if __name__ == "__main__":
    main()
