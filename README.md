# Basic Antivirus Simulation (Signature Scanner + VirusTotal)

An educational Python project demonstrating how real antivirus engines work —
with two-layer threat detection: local signature matching AND live VirusTotal
cloud intelligence.

---

## What It Does

| Feature | Description |
|---|---|
| File Hashing | Computes SHA-256 fingerprint of every file |
| Layer 1 — Local DB | Compares hash against signatures.json instantly (offline) |
| Layer 2 — VirusTotal | Checks unknown hashes against 70+ real AV engines via API |
| Folder Scanner | Recursively scans every file in a directory tree |
| Quarantine | Moves detected threats to an isolated folder (not deleted) |
| Audit Logging | Appends every scan event with timestamp to scan_log.txt |
| VT Cache | Saves VT results locally so the same hash is never queried twice |
| GUI Dashboard | Browser-based interactive dashboard (dashboard.html) |
| HTML Report | Full scan report with stats, file table, and log |

---

## Quick Start

### Step 1 — Set up demo environment
```
python antivirus.py setup-demo
```

### Step 2 — Scan (local only)
```
python antivirus.py scan test_folder/
```

### Step 3 — Scan with VirusTotal (real intelligence)
```
python antivirus.py scan test_folder/ --virustotal
```

### Step 4 — Scan and quarantine
```
python antivirus.py scan test_folder/ --virustotal --quarantine
```

### Step 5 — Generate HTML report
```
python report_generator.py --log scan_log.txt --out report.html
```

---

## VirusTotal Setup (free)

1. Go to https://www.virustotal.com and sign up free
2. Click your username (top right) then My API key
3. Copy the key
4. Open virustotal_lookup.py and replace line 14:
   VT_API_KEY = "PASTE_YOUR_KEY_HERE"
5. Run: pip install requests

Free tier: 4 lookups/minute, 500/day, 15,500/month.
Already-checked hashes are cached in vt_cache.json automatically.

---

## Signature Database

```
python antivirus.py list-sigs
python antivirus.py add-sig file.exe --label "Trojan.X"
```

---

## Project Structure

```
antivirus_sim/
|
|-- antivirus.py            <- Main scanner, all core logic, CLI entry point
|-- virustotal_lookup.py    <- VirusTotal API module (Layer 2 detection)
|-- demo_setup.py           <- Creates demo test files and signatures
|-- report_generator.py     <- Generates HTML scan report from log
|-- dashboard.html          <- Interactive browser GUI dashboard
|
|-- signatures.json         <- Local malware hash database     (auto-created)
|-- vt_cache.json           <- VT lookup cache                 (auto-created)
|-- scan_log.txt            <- Timestamped audit log           (auto-created)
|-- quarantine/             <- Isolated threat files           (auto-created)
|
`-- test_folder/            <- Demo scan target                (auto-created)
    |-- documents/
    |   |-- report.txt              clean
    |   |-- notes.txt               clean
    |   |-- resume.txt              clean
    |   `-- invoice.pdf.exe         SIMULATED MALWARE
    `-- downloads/
        |-- installer.exe           clean
        |-- photo.jpg               clean
        |-- free_game.exe           SIMULATED MALWARE
        `-- crack.zip               SIMULATED MALWARE
```

---

## How It Works — Two-Layer Detection

```
File on Disk
     |
     v
compute_hash()  --  SHA-256 fingerprint
     |
     v
LAYER 1: Check signatures.json        (offline, instant)
     |-- MATCH  --> THREAT [LOCAL] --> quarantine --> log
     |-- NO MATCH --> go to Layer 2
     |
     v (only if --virustotal flag used)
LAYER 2: VirusTotal API               (real cloud, 70+ engines)
     |-- check vt_cache.json first
     |-- if not cached --> call VT API --> cache result
     |-- 3+ engines flagged --> THREAT [VIRUSTOTAL] --> quarantine --> log
     `-- else --> CLEAN --> log
```

---

## Key Concepts Demonstrated

| Concept | Where in code |
|---|---|
| SHA-256 hashing | compute_hash() in antivirus.py |
| Signature matching | scan_file() Layer 1 check |
| Cloud threat intelligence | check_virustotal() in virustotal_lookup.py |
| Rate limiting | time.sleep(15) between VT API calls |
| Cache to save API quota | vt_cache.json in virustotal_lookup.py |
| Quarantine (not delete) | quarantine_file() using shutil.move() |
| Audit logging | log_event() append mode file write |
| Recursive folder scan | Path.rglob() in scan_folder() |
| False negative limitation | Modified malware = new hash = evades Layer 1 |

---

## Notes

- Educational use only — simulated malware files contain plain text, not real malware
- Layer 2 requires internet connection and a free VirusTotal account
- VT threshold is 3 engines to avoid false positives from noisy AV engines
- Real AV engines also use heuristics and behavioural analysis on top of signatures

---

## Extensions Completed

- [x] VirusTotal API integration (real threat intelligence)
- [x] GUI dashboard (dashboard.html)
- [x] HTML report generator (report_generator.py)
- [x] Local cache to protect API quota (vt_cache.json)

## Further Extension Ideas

1. Add YARA rule scanning for pattern-based detection
2. Implement real-time folder monitoring with the watchdog library
3. Add heuristic detection (double extensions like .pdf.exe, executables in temp)
4. Encrypt quarantined files so they cannot accidentally execute
5. Add email alerts when a threat is detected
