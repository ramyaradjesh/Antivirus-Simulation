# 🛡️ Basic Antivirus Simulation (Signature Scanner)

An educational Python project demonstrating how **signature-based antivirus engines** work.

---

## 📌 What It Does

| Feature | Description |
|---|---|
| **File Hashing** | Computes SHA-256 hashes of files |
| **Signature Matching** | Compares hashes against a known malware database |
| **Folder Scanner** | Recursively scans every file in a directory |
| **Quarantine** | Moves detected threats to an isolated folder |
| **Logging** | Appends all events to `scan_log.txt` |
| **Signature DB** | Add new malware signatures via CLI |

---

## 🚀 Quick Start

### 1. Set up the demo environment
```bash
python antivirus.py setup-demo
```
This creates:
- `test_folder/` — mix of clean and simulated malware files
- `signatures.json` — pre-populated signature database

### 2. Scan the test folder
```bash
python antivirus.py scan test_folder
```

### 3. Scan AND quarantine threats
```bash
python antivirus.py scan test_folder --quarantine
```
Detected malware is moved to `quarantine/`.

### 4. Scan a single file
```bash
python antivirus.py scan test_folder/downloads/free_game.exe
```

---

## 🗄️ Signature Database

### List all known signatures
```bash
python antivirus.py list-sigs
```

### Add a new file as a known threat
```bash
python antivirus.py add-sig suspicious_file.exe --label "Trojan.Example"
```
This hashes the file and adds it to `signatures.json`.

---

## 📁 Project Structure

```
antivirus_sim/
├── antivirus.py       ← Main scanner (entry point)
├── demo_setup.py      ← Creates demo files & signatures
├── signatures.json    ← Malware hash database (auto-generated)
├── scan_log.txt       ← Scan history log (auto-generated)
├── quarantine/        ← Isolated threats (auto-generated)
└── test_folder/       ← Demo scan target (auto-generated)
    ├── documents/
    │   ├── report.txt          (clean)
    │   ├── notes.txt           (clean)
    │   ├── resume.txt          (clean)
    │   └── invoice.pdf.exe     ⚠️ SIMULATED MALWARE
    └── downloads/
        ├── installer.exe       (clean)
        ├── photo.jpg           (clean)
        ├── free_game.exe       ⚠️ SIMULATED MALWARE
        └── crack.zip           ⚠️ SIMULATED MALWARE
```

---

## 🔬 How It Works (Concepts)

```
File on Disk
     │
     ▼
SHA-256 Hash  ←── hashlib.sha256()
     │
     ▼
Compare against signatures.json  ←── known malware hashes
     │
     ├── MATCH  →  🚨 THREAT DETECTED → (optional) quarantine
     │
     └── NO MATCH  →  ✅ CLEAN
```

### Key Concepts Demonstrated
- **Cryptographic Hashing**: SHA-256 fingerprints files uniquely
- **Signature Database**: JSON store mapping hash → malware name
- **False Negatives**: Modified malware bypasses signature scanning
- **Quarantine Logic**: Moving (not deleting) threats preserves forensic value
- **Audit Logging**: Every scan event is timestamped

---

## ⚠️ Notes

- **Educational use only** — does not detect real malware
- The "malware" files are plain text with fake content — completely safe
- To detect real malware, you'd need real threat intelligence hash databases
- Real AV engines also use heuristics, behavioral analysis, and cloud lookups

---

## 💡 Extension Ideas

1. Add **YARA rule** scanning for pattern-based detection
2. Implement **real-time monitoring** with `watchdog` library
3. Add a **GUI** with `tkinter` or `PyQt`
4. Integrate a **VirusTotal API** lookup for real hash checking
5. Add **heuristic scanning** (detect suspicious file names, double extensions)
