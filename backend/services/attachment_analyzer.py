"""
=============================================================================
Module: backend.services.attachment_analyzer
=============================================================================
Defensive Security Service: Static Attachment & Filename Risk Analysis.

DEFENSIVE SECURITY PRINCIPLES:
1. NEVER execute untrusted attachments or scripts.
2. Malicious actors frequently disguise executables using double extensions
   (e.g., 'document.pdf.exe') to exploit operating systems that hide known
   file extensions by default.
3. Macro-enabled office documents (.docm, .xlsm) and script engines (.vbs, .js, .ps1)
   represent primary delivery vehicles for droppers and infostealers.
4. This analyzer performs static, offline metadata examination only.
=============================================================================
"""

import os
import re
from typing import Dict, List, Any


# Dangerous file extensions commonly blocked by enterprise secure email gateways
DANGEROUS_EXTENSIONS = {
    # Direct executables & screensavers
    ".exe": ("Executable Binary", "CRITICAL", 45),
    ".scr": ("Screensaver Executable", "CRITICAL", 45),
    ".com": ("DOS Command Binary", "CRITICAL", 40),
    ".pif": ("Program Information File", "CRITICAL", 40),
    # Windows scripting & commands
    ".bat": ("Batch Shell Script", "HIGH", 35),
    ".cmd": ("Windows Command Script", "HIGH", 35),
    ".vbs": ("VBScript File", "HIGH", 35),
    ".vbe": ("VBScript Encoded Script", "HIGH", 35),
    ".js":  ("JScript / JavaScript File", "HIGH", 35),
    ".jse": ("JScript Encoded Script", "HIGH", 35),
    ".wsf": ("Windows Script File", "HIGH", 35),
    ".wsh": ("Windows Script Host Settings", "HIGH", 30),
    ".ps1": ("PowerShell Script", "HIGH", 35),
    ".psm1": ("PowerShell Module Script", "HIGH", 35),
    ".hta": ("HTML Application", "CRITICAL", 40),
    # Office Macro-enabled formats
    ".docm": ("Macro-Enabled Word Document", "HIGH", 30),
    ".xlsm": ("Macro-Enabled Excel Spreadsheet", "HIGH", 30),
    ".pptm": ("Macro-Enabled PowerPoint Presentation", "HIGH", 30),
    # Java & Disk images
    ".jar": ("Java Archive Executable", "HIGH", 30),
    ".iso": ("Optical Disk Image Container", "MEDIUM", 25),
    ".img": ("Disk Image File", "MEDIUM", 25),
    ".vhd": ("Virtual Hard Disk Image", "MEDIUM", 25),
}

# Archive extensions that often require sandboxing / decompression inspection
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}

# Generally benign document/media extensions
SAFE_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv", ".png", ".jpg", ".jpeg"}


def analyze_attachment(filename: str) -> Dict[str, Any]:
    """
    Statically analyzes an attachment filename for weaponized extensions,
    double-extension spoofing, and evasion tactics.

    Args:
        filename: Attachment filename (e.g. 'Invoice_482.pdf.exe')

    Returns:
        Structured dictionary with risk score (0-100), findings, and classification.
    """
    if not filename or not filename.strip():
        return {
            "has_attachment": False,
            "filename": "",
            "attachment_risk_score": 0,
            "is_double_extension": False,
            "primary_extension": "",
            "findings": []
        }

    clean_filename = filename.strip()
    name_lower = clean_filename.lower()
    
    findings: List[Dict[str, str]] = []
    risk_score = 0
    
    # 1. Parse extensions
    parts = name_lower.split(".")
    has_multiple_dots = len(parts) > 2
    
    # Primary (actual) extension is the final part
    primary_ext = f".{parts[-1]}" if len(parts) > 1 else ""
    secondary_ext = f".{parts[-2]}" if len(parts) > 2 else ""

    # 2. Check for Double Extension Obfuscation
    # Example: 'invoice.pdf.exe', 'contract.docx.vbs'
    is_double_extension = False
    if has_multiple_dots and primary_ext in DANGEROUS_EXTENSIONS:
        if secondary_ext in SAFE_EXTENSIONS or secondary_ext in [".pdf", ".doc", ".xls", ".txt"]:
            is_double_extension = True
            risk_score += 40
            findings.append({
                "severity": "CRITICAL",
                "indicator": f"Double Extension Deception ({secondary_ext}{primary_ext})",
                "explanation": f"Filename '{clean_filename}' uses a double extension. Operating systems hiding known extensions will show '{parts[-2]}', tricking the user into executing a dangerous '{primary_ext}' file."
            })

    # 3. Direct Dangerous Extension Check
    if primary_ext in DANGEROUS_EXTENSIONS:
        desc, severity, weight = DANGEROUS_EXTENSIONS[primary_ext]
        risk_score += weight
        findings.append({
            "severity": severity,
            "indicator": f"High-Risk {desc} ({primary_ext})",
            "explanation": f"The attachment ends with '{primary_ext}' ({desc}). These formats can execute code directly upon opening and are heavily restricted in corporate environments."
        })

    # 4. Container / Archive Check
    elif primary_ext in ARCHIVE_EXTENSIONS:
        risk_score += 15
        findings.append({
            "severity": "LOW",
            "indicator": f"Compressed Archive Attachment ({primary_ext})",
            "explanation": f"File is an archive ({primary_ext}). Threat actors frequently compress malicious payloads to evade email perimeter content scanners."
        })

    # 5. Check if benign
    elif primary_ext in SAFE_EXTENSIONS:
        findings.append({
            "severity": "INFO",
            "indicator": f"Standard Document Extension ({primary_ext})",
            "explanation": f"Filename uses typical non-executable document format '{primary_ext}'."
        })
    else:
        # Unknown extension
        findings.append({
            "severity": "LOW",
            "indicator": f"Uncommon Extension ({primary_ext})",
            "explanation": f"Attachment uses an uncommon extension '{primary_ext}'. Exercise caution before opening."
        })

    # 6. Filename length or deceptive space padding
    if "  " in clean_filename:
        risk_score += 15
        findings.append({
            "severity": "MEDIUM",
            "indicator": "Excessive Whitespace in Filename",
            "explanation": "Multiple spaces detected in filename, a technique used to push the true file extension off-screen in UI dialogs."
        })

    final_attachment_score = min(max(risk_score, 0), 100)

    return {
        "has_attachment": True,
        "filename": clean_filename,
        "attachment_risk_score": final_attachment_score,
        "is_double_extension": is_double_extension,
        "primary_extension": primary_ext,
        "secondary_extension": secondary_ext if is_double_extension else "",
        "findings": findings
    }
