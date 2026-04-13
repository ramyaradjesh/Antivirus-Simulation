"""
heuristics.py — Layer 3: Heuristic Detection Engine

Detects suspicious files based on HOW THEY LOOK and BEHAVE,
not what we already know about them.

This catches brand new malware that has no signature yet.

Three checks:
  1. Double extension   — invoice.pdf.exe  (real type is .exe)
  2. Dangerous location — .exe in Temp/Downloads folder
  3. File size mismatch — .txt file that is 500MB
"""

import os

# ── Dangerous executable extensions ──────────────────────────────────────────
# These file types can run code on your computer.
# Finding them in suspicious places or with fake extensions is a red flag.
DANGEROUS_EXTENSIONS = {
    ".exe",   # Windows executable
    ".bat",   # Batch script
    ".cmd",   # Command script
    ".vbs",   # Visual Basic script
    ".ps1",   # PowerShell script
    ".js",    # JavaScript
    ".jar",   # Java archive (can run code)
    ".scr",   # Screen saver (often malware)
    ".pif",   # Program Information File (often malware)
    ".com",   # Command file
    ".msi",   # Windows installer
}

# ── Suspicious folder names ───────────────────────────────────────────────────
# Legitimate software almost never lives in these locations.
# Malware loves hiding here because users rarely look.
SUSPICIOUS_LOCATIONS = [
    "temp",
    "tmp",
    "appdata",
    "recycle",
    "recycler",
    "$recycle.bin",
]

# ── File size limits per extension (in bytes) ─────────────────────────────────
# If a file is WAY outside the normal size for its type, something is wrong.
# Format: { ".extension": (min_bytes, max_bytes) }
SIZE_RULES = {
    ".txt":  (0,        10_000_000),    # Text: max 10MB
    ".jpg":  (1_000,    20_000_000),    # JPEG: min 1KB, max 20MB
    ".jpeg": (1_000,    20_000_000),
    ".png":  (67,       20_000_000),    # PNG: min 67 bytes (smallest valid PNG)
    ".gif":  (35,       10_000_000),
    ".pdf":  (67,       100_000_000),   # PDF: min 67 bytes (smallest valid PDF)
    ".docx": (1_000,    100_000_000),
    ".xlsx": (1_000,    100_000_000),
    ".mp3":  (1_000,    100_000_000),
    ".mp4":  (1_000,    2_000_000_000), # Video: up to 2GB
    ".zip":  (22,       2_000_000_000), # ZIP: min 22 bytes (empty zip)
}


def check_double_extension(filepath: str) -> dict:
    """
    Check 1 — Double Extension Detection

    A file like invoice.pdf.exe has TWO extensions.
    The real extension is always the LAST one (.exe).
    The fake extension (.pdf) is there to trick the user.

    Returns a finding dict if suspicious, None if clean.
    """
    filename   = os.path.basename(filepath)
    parts      = filename.split(".")

    # Need at least 3 parts: name + fake_ext + real_ext
    # e.g. ["invoice", "pdf", "exe"]
    if len(parts) < 3:
        return None

    real_ext = "." + parts[-1].lower()   # last extension = real type
    fake_ext = "." + parts[-2].lower()   # second to last = fake type

    # Only suspicious if the REAL extension is dangerous
    # AND the fake extension looks innocent
    innocent_extensions = {".pdf", ".txt", ".doc", ".jpg", ".png", ".mp3", ".mp4", ".xlsx"}

    if real_ext in DANGEROUS_EXTENSIONS and fake_ext in innocent_extensions:
        return {
            "check":       "double_extension",
            "reason":      f"Double extension detected: fake='{fake_ext}' real='{real_ext}'",
            "severity":    "HIGH",
            "detail":      f"File appears to be '{fake_ext}' but is actually '{real_ext}' — classic malware trick",
        }

    return None


def check_dangerous_location(filepath: str) -> dict:
    """
    Check 2 — Dangerous Location Detection

    Legitimate software lives in Program Files or Windows/System32.
    A random .exe in your Temp folder or Downloads folder is suspicious.

    Returns a finding dict if suspicious, None if clean.
    """
    filepath_lower = filepath.lower()
    filename       = os.path.basename(filepath)
    ext            = os.path.splitext(filename)[1].lower()

    # Only check executable file types
    if ext not in DANGEROUS_EXTENSIONS:
        return None

    # Check if it lives in a suspicious location
    for location in SUSPICIOUS_LOCATIONS:
        if location in filepath_lower:
            return {
                "check":    "dangerous_location",
                "reason":   f"Executable '{ext}' found in suspicious location: '{location}'",
                "severity": "MEDIUM",
                "detail":   f"Legitimate programs rarely live in '{location}' folders",
            }

    return None


def check_file_size(filepath: str) -> dict:
    """
    Check 3 — File Size Mismatch Detection

    A .txt file that is 500MB is impossible for normal text.
    A .jpg image that is 0 bytes is not a real image.
    These mismatches suggest the file extension is lying about what the file is.

    Returns a finding dict if suspicious, None if clean.
    """
    filename = os.path.basename(filepath)
    ext      = os.path.splitext(filename)[1].lower()

    # Only check extensions we have rules for
    if ext not in SIZE_RULES:
        return None

    try:
        file_size          = os.path.getsize(filepath)
        min_size, max_size = SIZE_RULES[ext]

        if file_size < min_size:
            return {
                "check":    "size_mismatch",
                "reason":   f"File too small for type '{ext}': {file_size} bytes (minimum: {min_size})",
                "severity": "MEDIUM",
                "detail":   f"A real '{ext}' file should be at least {_human_size(min_size)}",
            }

        if file_size > max_size:
            return {
                "check":    "size_mismatch",
                "reason":   f"File too large for type '{ext}': {_human_size(file_size)} (maximum: {_human_size(max_size)})",
                "severity": "MEDIUM",
                "detail":   f"A '{ext}' file of {_human_size(file_size)} is abnormally large",
            }

    except OSError:
        pass

    return None


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human readable string like 4.2 MB."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def run_heuristics(filepath: str) -> dict:
    """
    Run ALL three heuristic checks on a file.

    Returns a result dict:
    {
        "status":   "SUSPICIOUS" or "CLEAN"
        "findings": list of finding dicts (one per triggered check)
        "summary":  human-readable summary string
    }
    """
    findings = []

    # Run all three checks
    checks = [
        check_double_extension(filepath),
        check_dangerous_location(filepath),
        check_file_size(filepath),
    ]

    # Collect any checks that found something
    for finding in checks:
        if finding is not None:
            findings.append(finding)

    if findings:
        # Build a summary of all findings
        reasons  = " | ".join(f["reason"] for f in findings)
        severity = "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "MEDIUM"
        return {
            "status":   "SUSPICIOUS",
            "findings": findings,
            "severity": severity,
            "summary":  f"Heuristic ({len(findings)} flag{'s' if len(findings)>1 else ''}): {reasons}",
        }

    return {
        "status":   "CLEAN",
        "findings": [],
        "severity": None,
        "summary":  "No heuristic flags",
    }


# ── Quick test — run this file directly to test heuristics ───────────────────
if __name__ == "__main__":
    test_cases = [
        "documents/invoice.pdf.exe",      # double extension — HIGH
        "downloads/free_game.exe",        # dangerous location — MEDIUM
        "C:/Users/HP/AppData/Temp/x.bat", # dangerous location — MEDIUM
        "documents/report.txt",           # clean
        "downloads/photo.jpg",            # clean
    ]

    print("\n" + "="*60)
    print("  Heuristics Test Run")
    print("="*60)

    for path in test_cases:
        result = run_heuristics(path)
        icon   = "SUSPICIOUS" if result["status"] == "SUSPICIOUS" else "CLEAN    "
        print(f"\n  [{icon}] {os.path.basename(path)}")
        if result["findings"]:
            for f in result["findings"]:
                print(f"    [{f['severity']}] {f['reason']}")
                print(f"           {f['detail']}")
        else:
            print(f"    No flags raised")

    print("\n" + "="*60)
