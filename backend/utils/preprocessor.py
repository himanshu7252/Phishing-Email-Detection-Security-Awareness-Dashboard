"""
=============================================================================
Module: backend.utils.preprocessor
=============================================================================
Cybersecurity Preprocessing Pipeline for Email and Threat Artifacts.

DESIGN PHILOSOPHY:
In general Natural Language Processing (NLP), standard preprocessing often
involves aggressive text cleaning: stripping punctuation, dropping digits,
removing stop words, and converting everything to lowercase.

IN CYBERSECURITY & PHISHING DETECTION, AGGRESSIVE CLEANING DESTROYS EVIDENCE:
1. Punctuation (e.g. '!!!', '$$$') signals urgency and financial coercion.
2. Casing (e.g. 'URGENT IMMEDIATE ACTION REQUIRED') is an indicator of pressure.
3. Raw URLs, IP addresses, and query parameters contain direct attack vectors.
4. Sender display-name formatting reveals spoofing / brand impersonation.

This preprocessor extracts artifacts cleanly while preserving critical signals.
=============================================================================
"""

import re
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Tuple, Optional


# Regular expressions for threat artifact extraction
URL_REGEX = re.compile(
    r'(?:https?://|http://|www\d{0,3}[.]|[a-zA-Z0-9.\-]+[.][a-zA-Z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’])',
    re.IGNORECASE
)

EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+', re.IGNORECASE)
SENDER_PARSER_REGEX = re.compile(r'(?:"?([^"<]+)"?\s*)?<?([\w\.-]+@[\w\.-]+\.\w+)>?', re.IGNORECASE)


def extract_urls(text: str) -> List[str]:
    """
    Extracts all HTTP/HTTPS and bare domain URLs from a text string.
    Ensures deduplicated list while preserving order.
    """
    if not text:
        return []
    raw_urls = URL_REGEX.findall(text)
    
    # URL_REGEX returns tuples due to capturing groups; extract matched strings
    found_urls = []
    for match in re.finditer(URL_REGEX, text):
        url = match.group(0).strip('.,;:\'\"()[]{}<>')
        if url and url not in found_urls:
            found_urls.append(url)
    return found_urls


def parse_sender_string(sender_raw: str) -> Tuple[str, str, str]:
    """
    Parses a raw email 'From' string into:
    (display_name, email_address, domain)

    Examples:
        'Alice Smith <alice@example.org>' -> ('Alice Smith', 'alice@example.org', 'example.org')
        'support@invalid.test' -> ('', 'support@invalid.test', 'invalid.test')
    """
    if not sender_raw:
        return "", "", ""
        
    sender_raw = sender_raw.strip()
    match = SENDER_PARSER_REGEX.search(sender_raw)
    
    if match:
        display_name = (match.group(1) or "").strip()
        email_addr = (match.group(2) or "").strip().lower()
        domain = email_addr.split("@")[-1] if "@" in email_addr else ""
        return display_name, email_addr, domain
        
    if "@" in sender_raw:
        parts = sender_raw.strip("<> ").lower().split("@")
        domain = parts[-1]
        return "", sender_raw, domain
        
    return sender_raw, "", ""


def parse_eml_content(file_bytes: bytes) -> Dict[str, str]:
    """
    Safely parses raw RFC 822 / MIME (.eml or .txt) email bytes without
    executing or rendering any active scripts or remote resources.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
        
        sender = msg.get("from", "")
        subject = msg.get("subject", "")
        body = ""
        
        # Safely extract plain text body
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get("Content-Disposition", ""))
                
                # Skip active attachments
                if "attachment" in cdispo:
                    continue
                
                if ctype == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace") + "\n"
                    except Exception:
                        pass
                elif ctype == "text/html" and not body:
                    try:
                        raw_html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                        # Basic tag stripping without parsing scripts
                        body += re.sub(r'<[^>]+>', ' ', raw_html)
                    except Exception:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                body = str(msg.get_payload())
                
        # Find potential attachment names
        attachment_names = []
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                fname = part.get_filename()
                if fname:
                    attachment_names.append(fname)
                    
        return {
            "sender": sender,
            "subject": subject,
            "body": body.strip(),
            "attachment_name": ", ".join(attachment_names) if attachment_names else ""
        }
    except Exception as e:
        # Fallback to UTF-8 text interpretation if MIME parse fails
        try:
            text = file_bytes.decode("utf-8", errors="replace")
            return {
                "sender": "",
                "subject": "",
                "body": text,
                "attachment_name": ""
            }
        except Exception:
            return {"sender": "", "subject": "", "body": "", "attachment_name": ""}


def compute_text_metrics(text: str) -> Dict[str, float]:
    """
    Computes linguistic, punctuation, and structural threat metrics.
    """
    if not text:
        return {
            "char_count": 0,
            "word_count": 0,
            "uppercase_ratio": 0.0,
            "exclamation_count": 0,
            "question_count": 0,
            "dollar_count": 0
        }
        
    char_count = len(text)
    alpha_chars = sum(1 for c in text if c.isalpha())
    upper_chars = sum(1 for c in text if c.isupper())
    
    uppercase_ratio = (upper_chars / alpha_chars) if alpha_chars > 0 else 0.0
    
    return {
        "char_count": char_count,
        "word_count": len(text.split()),
        "uppercase_ratio": round(uppercase_ratio, 3),
        "exclamation_count": text.count("!"),
        "question_count": text.count("?"),
        "dollar_count": text.count("$")
    }
