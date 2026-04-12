"""
demo_setup.py — Creates a demo environment with:
  • Simulated clean files
  • Simulated malware files
  • Pre-populated signature database
"""

import os
import hashlib
import json


SIGNATURES_DB = "signatures.json"
SCAN_TARGET = "test_folder"


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def create_demo_environment():
    print("\n[*] Setting up demo environment...\n")

    os.makedirs(SCAN_TARGET, exist_ok=True)
    os.makedirs(os.path.join(SCAN_TARGET, "documents"), exist_ok=True)
    os.makedirs(os.path.join(SCAN_TARGET, "downloads"), exist_ok=True)

    # ── Clean files ──────────────────────────────────────────────────────────
    clean_files = {
        "documents/report.txt": b"This is a legitimate business report. Q3 earnings look great.",
        "documents/notes.txt": b"Meeting notes: discuss roadmap for next quarter.",
        "documents/resume.txt": b"John Doe | Python Developer | 5 years experience.",
        "downloads/installer.exe": b"LEGITIMATE_INSTALLER_BINARY_PLACEHOLDER_DATA_XYZ",
        "downloads/photo.jpg": b"JPEG_PLACEHOLDER_DATA_NOT_A_REAL_IMAGE_CLEAN_FILE",
    }

    for rel_path, content in clean_files.items():
        full_path = os.path.join(SCAN_TARGET, rel_path)
        with open(full_path, "wb") as f:
            f.write(content)
        print(f"  ✅ Created clean file : {full_path}")

    # ── Malware simulation files ─────────────────────────────────────────────
    # We define their content FIRST, then hash it to build the DB.
    malware_files = {
        "downloads/free_game.exe": {
            "content": b"MALWARE_SIM::TROJAN_DROPPER::PAYLOAD_ALPHA_001",
            "label": "Trojan.Dropper.Alpha",
        },
        "documents/invoice.pdf.exe": {
            "content": b"MALWARE_SIM::RANSOMWARE::LOCKY_VARIANT_2024",
            "label": "Ransomware.Locky.Variant",
        },
        "downloads/crack.zip": {
            "content": b"MALWARE_SIM::SPYWARE::KEYLOGGER_BETA_99",
            "label": "Spyware.Keylogger.Beta",
        },
    }

    signatures = {}

    for rel_path, info in malware_files.items():
        full_path = os.path.join(SCAN_TARGET, rel_path)
        content = info["content"]
        label = info["label"]

        with open(full_path, "wb") as f:
            f.write(content)

        file_hash = sha256(content)
        signatures[file_hash] = {"name": label, "added": "demo"}
        print(f"  🚨 Created malware sim: {full_path}  [{label}]")

    # ── Save signature database ──────────────────────────────────────────────
    with open(SIGNATURES_DB, "w") as f:
        json.dump(signatures, f, indent=2)

    print(f"\n  📁 Signature DB saved  : {SIGNATURES_DB}  ({len(signatures)} entries)")
    print(f"\n{'─'*60}")
    print("  Demo ready! Now run:")
    print(f"    python antivirus.py scan {SCAN_TARGET}")
    print(f"    python antivirus.py scan {SCAN_TARGET} --quarantine")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    create_demo_environment()
