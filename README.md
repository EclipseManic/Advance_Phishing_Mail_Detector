Advance Phishing Mail Detector

Author: EclipseManic

A Python-based phishing email analyzer that inspects .eml files for malicious indicators.
It integrates with VirusTotal and leverages multiple detection techniques, including header analysis, domain reputation, link inspection, and attachment scanning.

🚀 Features

Header Analysis

Detects Return-Path and Reply-To mismatches

Validates SPF, DKIM, and DMARC results

Highlights suspicious authentication failures

Domain & IP Reputation

WHOIS-based domain age check

VirusTotal API scanning for domains and IPs

Homograph and punycode attack detection

Link & Attachment Scanning

Extracts links from email bodies, attachments, and even QR codes in images

Unshortens shortened URLs before scanning

VirusTotal file hash scans for attachments

Content Analysis

Detects urgent/financial scam keywords

Flags impersonation attempts (Microsoft, PayPal, Amazon, etc.)

Highlights suspicious links hosted on common abused services (Drive, Dropbox, OneDrive, etc.)

Final Verdict

Phishing score from 0 to 10

Labels emails as SAFE, CAUTIOUS, or UNSAFE

Provides detailed feedback for each risk detected

Reports

Optional structured JSON report for automation and record keeping

📦 Requirements

Python 3.8+

A valid VirusTotal API key

Install Dependencies

Clone the repository and install required libraries:

pip install -r requirements.txt

Environment Setup: VirusTotal API Key

This script requires a VirusTotal API key. Without it, the tool will not run.

Get a free API key from: VirusTotal → My API Key

Set it as an environment variable before running the script.

On Linux / macOS:
export VT_API_KEY="your_api_key_here"

On Windows (permanent, PowerShell):
setx VT_API_KEY "your_api_key_here"


(Restart your terminal after running this for the variable to take effect.)

On Windows (temporary, current session only):
$env:VT_API_KEY="your_api_key_here"

🔧 Usage

Basic command:

python Advance_Phising_Mail_detector.py <email_file.eml>


Example with JSON report:

python Advance_Phising_Mail_detector.py suspicious_mail.eml --report analysis.json


Arguments:

<email_file.eml> → Path to the .eml email file

--report analysis.json → Saves a JSON report of the analysis

📝 Output

Header Analysis → Authentication checks, domain spoofing, mismatches

Reputation Scanning → VirusTotal results for domains and IPs

Link & Attachment Scanning → Flags malicious or suspicious URLs/files

Final Verdict → Phishing Score + Verdict (SAFE / CAUTIOUS / UNSAFE)

JSON Report → If --report option is used

📂 Example JSON Report
{
  "file": "suspicious_mail.eml",
  "verdict": "UNSAFE",
  "score": 8,
  "feedback": [
    "Return-Path Mismatch: Possible spoofing.",
    "DMARC Failure: Sender is forged.",
    "Malicious Links: 2 flagged as unsafe."
  ],
  "details": {
    "header_findings": {...},
    "spoof_findings": {...},
    "reputation_results": [...],
    "url_results": [...],
    "attachment_results": [...],
    "domain_age_days": 12
  }
}

⚠️ Disclaimer

This tool is designed strictly for educational and defensive security purposes.
Do not use it for offensive, malicious, or illegal activities.
The author assumes no liability for misuse.
