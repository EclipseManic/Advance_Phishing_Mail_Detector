import re
import email
import base64
import requests
import os
import time
import hashlib
import argparse
import json
import urllib.parse
import unicodedata
import html
from datetime import datetime
from io import BytesIO
from bs4 import BeautifulSoup

# --- Graceful import for optional libraries ---
# This makes the script runnable even if some advanced features are not installed.
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

# -------------------------------
# CONFIGURATION
# -------------------------------
# VirusTotal API key (optional). If absent, VirusTotal reputation/link/file scans will be skipped
API_KEY = os.getenv("VT_API_KEY")
VT_AVAILABLE = bool(API_KEY)

CONFIG = {
    "weights": {
        "mismatch_return_path": 2, "mismatch_reply_to": 2, "dmarc_fail": 7,
        "dmarc_other_fail": 2, "spf_fail": 2, "spf_not_found": 1, "dkim_fail": 2,
        "dkim_not_found": 1, "homograph_attack": 5, "malicious_link": 3,
        "malicious_domain": 4, "malicious_ip": 3, "urgent_keywords": 1,
        "high_risk_keywords": 4, "abused_service_link": 2, "recent_domain": 5,
        "javascript_present": 2, "impersonation_keywords": 3, "malicious_attachment": 10
    },
    "settings": {"domain_age_threshold_days": 90},
    "lists": {
        "abused_legit_services": ["docs.google.com", "drive.google.com", "onedrive.live.com", "dropbox.com", "forms.gle", "1drv.ms", "sharepoint.com"],
        "high_risk_keywords": ["wire transfer", "gift card", "crypto", "bitcoin", "urgent payment"],
        "impersonated_brands": ["microsoft", "office 365", "paypal", "amazon", "apple", "google", "docusign", "dropbox"]
    }
}

# -------------------------------
# COLOR & FORMATTING CONSTANTS
# -------------------------------
RED, GREEN, CYAN, YELLOW, MAGENTA, BLUE, BOLD, RESET = '\033[91m', '\033[92m', '\033[96m', '\033[93m', '\033[95m', '\033[94m', '\033[1m', '\033[0m'
CHECK, CROSS, INFO = '✔️', '❌', 'ℹ️'


# -------------------------------
# HELPER FUNCTIONS
# -------------------------------
def parse_eml_file(file_path):
    with open(file_path, 'rb') as file:
        msg = email.message_from_binary_file(file)
    header_text = "".join(f"{key}: {value}\n" for key, value in msg.items())
    body, html_body, attachments, images = "", "", [], []

    for part in msg.walk():
        try:
            # Backwards-compatible attachment detection:
            # Prefer get_content_disposition() when available, fall back to filename or application/* types.
            # Determine disposition/attachment more defensively
            is_attachment = False
            try:
                disp = None
                if hasattr(part, 'get_content_disposition'):
                    disp = part.get_content_disposition()
                filename = part.get_filename()
                ctype = part.get_content_type() or ''
                if disp == 'attachment' or filename:
                    is_attachment = True
                elif ctype.startswith('application/'):
                    is_attachment = True
            except Exception:
                is_attachment = False

            payload = part.get_payload(decode=True)
            # Attachments: store raw bytes if present; ensure filename exists
            if is_attachment:
                attachments.append({'filename': (part.get_filename() or 'unknown'), 'data': payload})
            elif ctype.startswith('image/'):
                if payload:
                    images.append(payload)
            elif ctype == 'text/plain':
                if isinstance(payload, bytes):
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        body += payload.decode(charset, errors='ignore')
                    except Exception:
                        body += payload.decode(errors='ignore')
                elif isinstance(payload, str):
                    body += payload
            elif ctype == 'text/html':
                if isinstance(payload, bytes):
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        html_body += payload.decode(charset, errors='ignore')
                    except Exception:
                        html_body += payload.decode(errors='ignore')
                elif isinstance(payload, str):
                    html_body += payload
        except Exception as e:
            print(f"{YELLOW}Warning: Could not process a part of the email. Error: {e}{RESET}")
    return header_text, body, html_body, attachments, images

def find_email_in_header(regex, header_text):
    match = re.search(regex, header_text, re.IGNORECASE)
    return match.groups()[-1].lower().strip() if match else None

def analyze_header(header_text):
    findings = {
        'From Address': find_email_in_header(r"From:.*<(.+?)>", header_text) or find_email_in_header(r"From:\s*([^\s<>]+@[^\s<>]+)", header_text),
        'Return-Path Address': find_email_in_header(r"Return-Path:\s*<(.+?)>", header_text),
        'Reply-To Address': find_email_in_header(r"Reply-To:.*<(.+?)>", header_text) or find_email_in_header(r"Reply-To:\s*([^\s<>]+@[^\s<>]+)", header_text)
    }
    findings['Return-Path Mismatch'] = (findings['From Address'] and findings['Return-Path Address'] and findings['Return-Path Address'] != findings['From Address'])
    findings['Reply-To Mismatch'] = (findings['From Address'] and findings['Reply-To Address'] and findings['Reply-To Address'] != findings['From Address'])

    # Use a more robust parser for Authentication-Results which can be folded across lines
    def parse_auth_results(hdr_text):
        out = {'spf': 'not found', 'dkim': 'not found', 'dmarc': 'not found'}
        try:
            # collect all Authentication-Results header instances (account for folded lines)
            matches = re.findall(r"Authentication-Results:[^\n]*(?:\n[ \t].*)*", hdr_text, re.IGNORECASE)
            if matches:
                joined = ' '.join(m.replace('\n', ' ') for m in matches)
                for key in ['spf', 'dkim', 'dmarc']:
                    m = re.search(fr"{key}\s*=\s*([A-Za-z0-9_-]+)", joined, re.IGNORECASE)
                    if m:
                        val = m.group(1).lower()
                        # normalize some variants
                        if val in ['temperror', 'timeout']:
                            val = 'neutral'
                        elif val in ['permerror']:
                            val = 'fail'
                        out[key] = val
        except Exception:
            pass
        return out

    auth = parse_auth_results(header_text)
    findings['SPF Result'] = auth.get('spf', 'not found')
    findings['DKIM Result'] = auth.get('dkim', 'not found')
    findings['DMARC Result'] = auth.get('dmarc', 'not found')
    return findings

def analyze_domain_for_spoofing(domain):
    if not domain: return {}
    findings = {'is_homograph_attack': False, 'punycode_version': None}
    if domain != unicodedata.normalize('NFKC', domain): findings['is_homograph_attack'] = True
    try:
        punycode = domain.encode('idna').decode('ascii')
        if punycode.startswith('xn--'): findings['punycode_version'] = punycode
    except UnicodeError: findings['is_homograph_attack'] = True
    return findings

def extract_links(text, is_html=False):
    urls = []
    if is_html and text:
        soup = BeautifulSoup(text, 'html.parser')
        urls.extend(a_tag['href'] for a_tag in soup.find_all('a', href=True) if a_tag['href'].startswith('http'))
    elif text:
        urls.extend(re.findall(r'https?://[^\s<>"]+', text))
    return list(set([html.unescape(url) for url in urls]))

def colorize_result(result_text):
    if "API rate limit" in result_text or "Error" in result_text: return f"{YELLOW}{INFO} {result_text}{RESET}"
    if re.match(r"([1-9]|[1-9][0-9])", result_text): return f"{RED}{CROSS} {result_text}{RESET}"
    if "0 of" in result_text: return f"{GREEN}{CHECK} {result_text}{RESET}"
    return f"{YELLOW}{INFO} {result_text}{RESET}"

def check_domain_age(domain):
    if not WHOIS_AVAILABLE: return None
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        if creation_date: return (datetime.now() - creation_date).days
    except Exception: return None
    return None

def scan_images_for_qrcodes(images_data):
    if not IMAGE_SCANNING_AVAILABLE: return []
    found_urls = []
    for img_data in images_data:
        try:
            img = Image.open(BytesIO(img_data))
            decoded_qrs = qr_decode(img)
            if decoded_qrs:
                found_urls.extend(qr.data.decode('utf-8') for qr in decoded_qrs if qr.data.decode('utf-8').startswith('http'))
            else:
                found_urls.extend(re.findall(r'https?://[^\s<>"]+', pytesseract.image_to_string(img)))
        except Exception as e:
            print(f"{YELLOW}Warning: Could not process an image. Error: {e}{RESET}")
    return list(set(found_urls))

def extract_links_from_attachment(attachment):
    if not ATTACHMENT_PARSING_AVAILABLE: return []
    filename, data = attachment.get('filename', '').lower(), attachment.get('data')
    if not data: return []
    
    text = ""
    try:
        if filename.endswith('.pdf'):
            with pdfplumber.open(BytesIO(data)) as pdf:
                text = "".join(page.extract_text() or "" for page in pdf.pages)
        elif filename.endswith('.docx'):
            doc = docx.Document(BytesIO(data))
            text = "\n".join(para.text for para in doc.paragraphs)
    except Exception as e:
        print(f"{YELLOW}Warning: Could not extract text from attachment '{filename}'. Error: {e}{RESET}")
    return list(set(re.findall(r'https?://[^\s<>"]+', text))) if text else []


# -------------------------------
# VIRUSTOTAL API FUNCTIONS
# -------------------------------
def scan_entity(entity_id, api_url_format):
    headers, vt_url = {"x-apikey": API_KEY}, api_url_format.format(entity_id)
    try:
        response = requests.get(vt_url, headers=headers, timeout=15)
        if response.status_code == 429: return "API rate limit exceeded"
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return f"{stats['malicious']} of {sum(stats.values())} engines flagged"
        elif response.status_code == 404: return "Not found in VirusTotal"
        else: return f"Error {response.status_code}"
    except requests.exceptions.RequestException as e: return f"Request Error: {str(e)}"

def scan_url(url):
    return scan_entity(base64.urlsafe_b64encode(url.encode()).decode().strip("="), "https://www.virustotal.com/api/v3/urls/{}")

def scan_file_hash(file_hash):
    return scan_entity(file_hash, "https://www.virustotal.com/api/v3/files/{}")

def scan_reputation(entity, entity_type):
    return scan_entity(entity, f"https://www.virustotal.com/api/v3/{entity_type}/{{}}")

def unshorten_url(url):
    try: return requests.head(url, allow_redirects=True, timeout=10).url
    except Exception: return url


# -------------------------------
# CORE LOGIC FUNCTIONSz
# -------------------------------
def generate_score_and_feedback(data):
    score, feedback_items = 0, []
    w = CONFIG['weights']

    if data['header_findings'].get('Return-Path Mismatch'):
        score += w['mismatch_return_path']
        feedback_items.append(f"{RED}{CROSS} Return-Path Mismatch:{RESET} A technique sometimes used for spoofing.")
    
    dmarc_res = data['header_findings'].get('DMARC Result')
    if dmarc_res == 'fail':
        score += w['dmarc_fail']
        feedback_items.append(f"{RED}{CROSS} DMARC Failure:{RESET} Critical sign that the sender is forged.")
    elif dmarc_res in ['none', 'not found', 'neutral']:
        # DMARC present but not passing (or not present) — smaller penalty
        score += w['dmarc_other_fail']
        feedback_items.append(f"{YELLOW}{INFO} DMARC Not Pass:{RESET} DMARC not evaluated as 'pass' (value: {dmarc_res}).")
    
    for auth in ['SPF', 'DKIM']:
        res = data['header_findings'].get(f'{auth} Result')
        if res not in ['pass', 'not found', 'neutral', 'none']:
            score += w[f'{auth.lower()}_fail']
            feedback_items.append(f"{RED}{CROSS} {auth} Failure:{RESET} Email failed this authentication check.")
        elif res == 'not found':
            score += w[f'{auth.lower()}_not_found']
            feedback_items.append(f"{YELLOW}{INFO} {auth} Missing:{RESET} Sender's domain lacks this protection.")

    if data['spoof_findings'].get('is_homograph_attack'):
        score += w['homograph_attack']
        feedback_items.append(f"{RED}{CROSS} Homograph Attack:{RESET} Sender's domain uses look-alike characters.")

    if data['domain_age'] is not None and data['domain_age'] < CONFIG['settings']['domain_age_threshold_days']:
        score += w['recent_domain']
        feedback_items.append(f"{RED}{CROSS} Recently Created Domain:{RESET} The sender's domain was created only {data['domain_age']} days ago.")

    for type, entity, result in data['reputation_results']:
        if re.match(r"([1-9]|[1-9][0-9])", result):
            score += w[f'malicious_{type}']
            feedback_items.append(f"{RED}{CROSS} Bad Reputation:{RESET} The {type} '{entity}' is flagged as malicious.")

    suspicious_links = sum(1 for _, res in data['url_results'] if re.match(r"([1-9]|[1-9][0-9])", res))
    if suspicious_links > 0:
        score += suspicious_links * w['malicious_link']
        feedback_items.append(f"{RED}{CROSS} Malicious Links:{RESET} {suspicious_links} link(s) flagged as unsafe.")
    
    if any(service in url for url, _ in data['url_results'] for service in CONFIG['lists']['abused_legit_services']):
        score += w['abused_service_link']
        feedback_items.append(f"{YELLOW}{INFO} Abused Service Link:{RESET} Contains a link to a file-sharing service often used by attackers.")

    full_text = data['full_body'].lower()
    if any(kw in full_text for kw in CONFIG['lists']['high_risk_keywords']):
        score += w['high_risk_keywords']
        feedback_items.append(f"{RED}{CROSS} High-Risk Keywords:{RESET} Found terms often used in financial scams.")

    if re.search(r'urgent|verify|password|account|confirm|suspended|invoice', full_text):
        score += w['urgent_keywords']
        feedback_items.append(f"{YELLOW}{INFO} Urgent Keywords:{RESET} Email contains words designed to create pressure.")
        if any(brand in full_text for brand in CONFIG['lists']['impersonated_brands']):
            score += w['impersonation_keywords']
            feedback_items.append(f"{RED}{CROSS} Brand Impersonation Likely:{RESET} Combines urgent language with brand names.")

    if data['javascript_present']:
        score += w['javascript_present']
        feedback_items.append(f"{YELLOW}{INFO} JavaScript Detected:{RESET} Email contains scripts that could hide malicious actions.")

    if any(re.match(r"([1-9]|[1-9][0-9])", res) for _, _, res in data['attachment_results']):
        score = w['malicious_attachment']
        feedback_items.append(f"{RED}{CROSS} Malicious Attachment:{RESET} A file was flagged as malware.")
    
    if all(data['header_findings'].get(f'{res} Result') == 'pass' for res in ['SPF', 'DKIM', 'DMARC']):
        feedback_items.append(f"{GREEN}{CHECK} Sender Identity Verified:{RESET} Email passed all authentication checks.")
    
    if (data['url_results'] or data['attachment_results']) and not suspicious_links and not any(re.match(r"([1-9]|[1-9][0-9])", res) for _, _, res in data['attachment_results']):
        feedback_items.append(f"{GREEN}{CHECK} Content Scan:{RESET} Links and attachments were scanned and appear to be safe.")

    return min(score, 10), feedback_items


# -------------------------------
# MAIN PROGRAM
# -------------------------------
def main():
    parser = argparse.ArgumentParser(description="Enhanced Phishing Email Analyzer")
    parser.add_argument("eml_file", help="Path to the .eml file to scan")
    parser.add_argument("--report", help="Path to save a detailed JSON analysis report", default=None)
    args = parser.parse_args()

    try:
        header_text, body, html_body, attachments, images = parse_eml_file(args.eml_file)
    except FileNotFoundError:
        print(f"{RED}Error: File not found: {args.eml_file}{RESET}")
        return

    findings = analyze_header(header_text)
    from_addr = findings.get('From Address')
    sender_domain = from_addr.split('@')[-1] if from_addr else None
    spoof_findings = analyze_domain_for_spoofing(sender_domain)

    print(f"\n{CYAN}{BOLD}========== HEADER ANALYSIS =========={RESET}")
    if findings.get('Return-Path Mismatch'): print(f"{RED}{CROSS} Return-Path Mismatch: {findings.get('Return-Path Address')} vs {from_addr}{RESET}")
    else: print(f"{GREEN}{CHECK} Return-Path matches From Address.{RESET}")
    
    if findings.get('Reply-To Mismatch'): print(f"{RED}{CROSS} Reply-To Mismatch: {findings.get('Reply-To Address')} vs {from_addr}{RESET}")
    
    for auth in ['SPF', 'DKIM', 'DMARC']:
        val = findings.get(f'{auth} Result')
        print(f"{BOLD}{BLUE}{auth} Result:{RESET} ", end='')
        if val == 'pass':
            print(f"{GREEN}{CHECK} Pass{RESET}")
        elif val in ['not found', 'none', 'neutral']:
            # 'none' is not necessarily a hard failure — it often means the domain's DMARC policy is set to 'none'
            # or that the message didn't meet alignment (no enforcement). Show as informational.
            if val == 'not found':
                print(f"{YELLOW}{INFO} Not Found{RESET}")
            elif val == 'none':
                print(f"{YELLOW}{INFO} None: DMARC policy is 'none' or alignment not met (no enforcement){RESET}")
            else:
                print(f"{YELLOW}{INFO} {val.capitalize()}{RESET}")
        else:
            print(f"{RED}{CROSS} {val.capitalize()} (Failed){RESET}")

    domain_age = check_domain_age(sender_domain) if sender_domain else None
    if domain_age is not None:
        age_color = RED if domain_age < CONFIG['settings']['domain_age_threshold_days'] else GREEN
        print(f"{BOLD}{BLUE}Domain Age:{RESET} {age_color}{domain_age} days old{RESET}")
    elif WHOIS_AVAILABLE == False and sender_domain:
        print(f"{YELLOW}{INFO} Domain Age check skipped: 'python-whois' library not found. Run 'pip install python-whois'.{RESET}")

    print(f"{CYAN}{BOLD}--------------------------------------{RESET}")
    received_headers = re.findall(r"Received: (.+)", header_text)
    print(f"{CYAN}{BOLD}Received Path:{RESET}")
    for hop in received_headers: print(f"{YELLOW}- {hop.strip()}{RESET}")

    display_name_match = re.search(r'From:\s*(.*?)\s*<', header_text, re.IGNORECASE)
    print(f"{CYAN}{BOLD}Display Name:{RESET} {(display_name_match.group(1).strip('\" ') if display_name_match else 'Not Found')}")
    print(f"{CYAN}{BOLD}Email Address:{RESET} {from_addr or 'Not Found'}")

    if spoof_findings.get('is_homograph_attack'): print(f"{RED}{CROSS} Homograph Attack Detected!{RESET}")
    if spoof_findings.get('punycode_version'): print(f"{YELLOW}{INFO} Punycode Domain Detected: {spoof_findings['punycode_version']}{RESET}")

    api_call_queue = []
    if sender_domain: api_call_queue.append(('domain', sender_domain))
    
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    private_ip_pattern = r'(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)'
    unique_ips = set(ip for ip in re.findall(ip_pattern, header_text) if not re.match(private_ip_pattern, ip))
    for ip in unique_ips: api_call_queue.append(('ip', ip))
    
    reputation_results = []
    if api_call_queue:
        print(f"\n{CYAN}{BOLD}========== REPUTATION SCANNING ({YELLOW}15s delay per item{CYAN}) =========={RESET}")
        for i, (entity_type, entity) in enumerate(api_call_queue):
            scan_type = 'domains' if entity_type == 'domain' else 'ip_addresses'
            result = scan_reputation(entity, scan_type)
            reputation_results.append((entity_type, entity, result))
            print(f"{BOLD}{BLUE}Scanned {entity_type.capitalize()}:{RESET} {entity} -> {colorize_result(result)}")
            if i < len(api_call_queue) - 1: time.sleep(16)

    urls_from_body = set(extract_links(body, is_html=False) + extract_links(html_body, is_html=True))
    urls_from_images = set(scan_images_for_qrcodes(images))
    urls_from_attachments = set()
    for att in attachments:
        urls_from_attachments.update(extract_links_from_attachment(att))
    
    all_unique_urls = list(urls_from_body | urls_from_images | urls_from_attachments)
    
    url_results = []
    if all_unique_urls:
        print(f"\n{CYAN}{BOLD}========== LINK SCANNING ({YELLOW}15s delay per link{CYAN}) =========={RESET}")
        if urls_from_images: print(f"{YELLOW}{INFO} Found {len(urls_from_images)} unique URL(s) inside images.{RESET}")
        if urls_from_attachments: print(f"{YELLOW}{INFO} Found {len(urls_from_attachments)} unique URL(s) inside attachments.{RESET}")
        
        for i, url in enumerate(all_unique_urls):
            final_url = unshorten_url(url)
            result = scan_url(final_url)
            url_results.append((final_url, result))
            print(f"{BOLD}{BLUE}Link:{RESET} {MAGENTA}{final_url}{RESET} -> {colorize_result(result)}")
            if i < len(all_unique_urls) - 1: time.sleep(16)

    attachment_results = []
    if attachments:
        print(f"\n{CYAN}{BOLD}========== ATTACHMENT SCANNING ({YELLOW}15s delay per file{CYAN}) =========={RESET}")
        for i, att in enumerate(attachments):
            file_hash = hashlib.sha256(att['data']).hexdigest()
            result = scan_file_hash(file_hash)
            attachment_results.append((att['filename'], file_hash, result))
            print(f"{BOLD}{BLUE}Attachment:{RESET} {MAGENTA}{att['filename']}{RESET} -> {colorize_result(result)}")
            if i < len(attachments) - 1: time.sleep(16)
            
    analysis_data = {
        'header_findings': findings, 'spoof_findings': spoof_findings, 'url_results': url_results,
        'attachment_results': attachment_results, 'reputation_results': reputation_results,
        'full_body': body + html_body, 'domain_age': domain_age,
        'javascript_present': '<script' in html_body.lower()
    }
    score, feedback_items = generate_score_and_feedback(analysis_data)
    
    if score >= 7: verdict, score_color = f"{RED}{BOLD}UNSAFE{RESET}", RED
    elif score >= 4: verdict, score_color = f"{YELLOW}{BOLD}CAUTIOUS{RESET}", YELLOW
    else: verdict, score_color = f"{GREEN}{BOLD}SAFE{RESET}", GREEN

    print(f"\n{CYAN}{BOLD}========== FINAL VERDICT =========={RESET}")
    print(f"{BOLD}{BLUE}Phishing Score:{RESET} {score_color}{BOLD}{score}/10{RESET}")
    print(f"{BOLD}{BLUE}Verdict:{RESET} {verdict}")

    print(f"\n{CYAN}{BOLD}========== DETAILED FEEDBACK =========={RESET}")
    if feedback_items:
        for item in feedback_items: print(item)
    else:
        print(f"{GREEN}{CHECK} No major risk factors were detected in this email.{RESET}")
    
    if args.report:
        report_data = {"file": args.eml_file, "verdict": re.sub(r'\033\[\d+m', '', verdict), "score": score,
            "feedback": [re.sub(r'\033\[\d+m', '', item) for item in feedback_items],
            "details": {"header_findings": findings, "spoof_findings": spoof_findings,
                "reputation_results": reputation_results, "url_results": url_results,
                "attachment_results": attachment_results, "domain_age_days": domain_age}}
        try:
            with open(args.report, 'w', encoding='utf-8') as f: json.dump(report_data, f, indent=4)
            print(f"\n{CYAN}Detailed analysis report saved to {args.report}{RESET}")
        except Exception as e:
            print(f"\n{RED}Error saving report: {e}{RESET}")

if __name__ == "__main__":
    main()
