"""
Basic Antivirus Simulation (Signature Scanner)
Educational tool demonstrating how signature-based antivirus engines work.
"""

import os
import hashlib
import shutil
import json
import datetime
from pathlib import Path


# ─── Malware Signature Database ─────────────────────────────────────────────
# In a real AV, these are cryptographic hashes of known malware files.
# Here we use pre-computed MD5/SHA256 hashes of our simulated malware files.
SIGNATURES_DB = "signatures.json"

# ─── Quarantine Folder ───────────────────────────────────────────────────────
QUARANTINE_DIR = "quarantine"

# ─── Scan Log ────────────────────────────────────────────────────────────────
LOG_FILE = "scan_log.txt"


def compute_hash(filepath: str, algorithm: str = "sha256") -> str:
    """Compute the cryptographic hash of a file."""
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, OSError) as e:
        return f"ERROR: {e}"


def load_signatures(db_path: str) -> dict:
    """Load known malware signatures from the JSON database."""
    if not os.path.exists(db_path):
        print(f"[!] Signature database '{db_path}' not found. Creating empty DB.")
        return {}
    with open(db_path, "r") as f:
        return json.load(f)


def save_signatures(db_path: str, signatures: dict):
    """Save the signature database to disk."""
    with open(db_path, "w") as f:
        json.dump(signatures, f, indent=2)
    print(f"[+] Signature database saved to '{db_path}'.")


def add_signature(db_path: str, filepath: str, label: str = None):
    """Add a file's hash to the malware signature database."""
    signatures = load_signatures(db_path)
    file_hash = compute_hash(filepath)
    name = label or os.path.basename(filepath)
    signatures[file_hash] = {"name": name, "added": str(datetime.datetime.now())}
    save_signatures(db_path, signatures)
    print(f"[+] Added signature: {file_hash[:16]}...  →  '{name}'")


def quarantine_file(filepath: str):
    """Move a detected malicious file to the quarantine folder."""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    dest = os.path.join(QUARANTINE_DIR, os.path.basename(filepath))
    # Avoid overwriting if file already quarantined
    if os.path.exists(dest):
        base, ext = os.path.splitext(dest)
        dest = f"{base}_{int(datetime.datetime.now().timestamp())}{ext}"
    shutil.move(filepath, dest)
    return dest


def log_event(message: str):
    """Append a log entry with timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    with open(LOG_FILE, "a") as log:
        log.write(entry + "\n")
    return entry


def scan_file(filepath: str, signatures: dict, quarantine: bool = False) -> dict:
    """
    Scan a single file against the signature database.
    Returns a result dict with status info.
    """
    result = {
        "file": filepath,
        "hash": None,
        "status": "CLEAN",
        "threat_name": None,
        "quarantined_to": None,
        "error": None,
    }

    if not os.path.isfile(filepath):
        result["error"] = "File not found"
        result["status"] = "ERROR"
        return result

    file_hash = compute_hash(filepath)
    result["hash"] = file_hash

    if file_hash in signatures:
        result["status"] = "THREAT"
        result["threat_name"] = signatures[file_hash]["name"]
        msg = f"THREAT DETECTED | {filepath} | {result['threat_name']} | {file_hash[:16]}..."
        log_event(msg)

        if quarantine:
            dest = quarantine_file(filepath)
            result["quarantined_to"] = dest
            log_event(f"QUARANTINED    | {filepath} → {dest}")
    else:
        log_event(f"CLEAN          | {filepath} | {file_hash[:16]}...")

    return result


def scan_folder(folder: str, signatures: dict, quarantine: bool = False) -> list:
    """
    Recursively scan all files in a folder.
    Returns a list of result dicts.
    """
    results = []
    folder_path = Path(folder)

    if not folder_path.exists():
        print(f"[!] Folder '{folder}' does not exist.")
        return results

    all_files = list(folder_path.rglob("*"))
    files_only = [f for f in all_files if f.is_file()]

    print(f"\n{'═'*60}")
    print(f"  🔍 Scanning: {folder}  ({len(files_only)} files)")
    print(f"{'═'*60}")

    threats = 0
    for filepath in files_only:
        # Skip quarantine folder itself
        if QUARANTINE_DIR in str(filepath):
            continue

        result = scan_file(str(filepath), signatures, quarantine)
        results.append(result)

        icon = "🚨" if result["status"] == "THREAT" else "✅"
        status_str = (
            f"THREAT [{result['threat_name']}]"
            if result["status"] == "THREAT"
            else result["status"]
        )
        hash_preview = result["hash"][:16] + "..." if result["hash"] else "N/A"
        print(f"  {icon}  {status_str:<35} {hash_preview}  {filepath.name}")

        if result["status"] == "THREAT":
            threats += 1
            if result["quarantined_to"]:
                print(f"      ↳ Quarantined to: {result['quarantined_to']}")

    print(f"\n{'─'*60}")
    print(f"  Scan complete. Files: {len(results)}  |  Threats: {threats}")
    print(f"{'─'*60}\n")
    return results


def print_report(results: list):
    """Print a summary report of the scan."""
    total = len(results)
    threats = [r for r in results if r["status"] == "THREAT"]
    clean = [r for r in results if r["status"] == "CLEAN"]
    errors = [r for r in results if r["status"] == "ERROR"]

    print("\n" + "═" * 60)
    print("  📋  SCAN REPORT")
    print("═" * 60)
    print(f"  Total files scanned : {total}")
    print(f"  ✅ Clean            : {len(clean)}")
    print(f"  🚨 Threats found    : {len(threats)}")
    print(f"  ⚠️  Errors          : {len(errors)}")

    if threats:
        print("\n  Detected threats:")
        for r in threats:
            q = f" → quarantined to {r['quarantined_to']}" if r["quarantined_to"] else ""
            print(f"    • {r['file']}  [{r['threat_name']}]{q}")

    print("═" * 60 + "\n")


# ─── CLI Entry Point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Basic Antivirus Simulation - Signature Scanner"
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_p = subparsers.add_parser("scan", help="Scan a file or folder")
    scan_p.add_argument("target", help="File or folder to scan")
    scan_p.add_argument(
        "--quarantine", "-q", action="store_true", help="Move threats to quarantine"
    )

    # add-sig command
    sig_p = subparsers.add_parser("add-sig", help="Add a file's hash to signature DB")
    sig_p.add_argument("file", help="File to add as malware signature")
    sig_p.add_argument("--label", "-l", help="Friendly name for this threat")

    # list-sigs command
    subparsers.add_parser("list-sigs", help="List all known signatures")

    # setup-demo command
    subparsers.add_parser("setup-demo", help="Create demo files for testing")

    args = parser.parse_args()

    # ── setup-demo ──
    if args.command == "setup-demo":
        from demo_setup import create_demo_environment
        create_demo_environment()

    # ── add-sig ──
    elif args.command == "add-sig":
        add_signature(SIGNATURES_DB, args.file, args.label)

    # ── list-sigs ──
    elif args.command == "list-sigs":
        sigs = load_signatures(SIGNATURES_DB)
        if not sigs:
            print("[i] No signatures in database.")
        else:
            print(f"\n{'─'*60}")
            print(f"  Signature Database  ({len(sigs)} entries)")
            print(f"{'─'*60}")
            for h, info in sigs.items():
                print(f"  {h[:32]}...  →  {info['name']}")
            print(f"{'─'*60}\n")

    # ── scan ──
    elif args.command == "scan":
        signatures = load_signatures(SIGNATURES_DB)
        target = args.target
        if os.path.isdir(target):
            results = scan_folder(target, signatures, args.quarantine)
        else:
            result = scan_file(target, signatures, args.quarantine)
            results = [result]
            icon = "🚨" if result["status"] == "THREAT" else "✅"
            print(f"\n{icon} {result['status']} — {result['file']}")
            if result["threat_name"]:
                print(f"   Threat: {result['threat_name']}")
            if result["quarantined_to"]:
                print(f"   Quarantined to: {result['quarantined_to']}")
        print_report(results)

    else:
        parser.print_help()
