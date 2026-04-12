"""
report_generator.py — Generates a detailed HTML scan report after a scan.
Run after antivirus.py scan to produce a polished, shareable report.

Usage:
  python report_generator.py --log scan_log.txt --out report.html
"""

import os
import json
import argparse
import datetime


REPORT_CSS = """
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f4f5f7; color: #1a1a1a; font-size: 14px; }
  .wrapper { max-width: 900px; margin: 2rem auto; padding: 0 1rem 3rem; }
  header { background: #1a2540; color: #fff; border-radius: 12px; padding: 2rem 2.5rem; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 1.5rem; }
  .shield-icon { font-size: 3rem; }
  header h1 { font-size: 1.5rem; font-weight: 600; }
  header p  { opacity: .65; margin-top: 4px; font-size: 13px; }
  .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 1.5rem; }
  .stat-card { background: #fff; border-radius: 10px; padding: 1.25rem 1rem; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
  .stat-value { font-size: 2.2rem; font-weight: 700; line-height: 1; }
  .stat-label { font-size: 12px; color: #666; margin-top: 4px; }
  .stat-card.clean .stat-value  { color: #1a8a5a; }
  .stat-card.threat .stat-value { color: #d94040; }
  .stat-card.total .stat-value  { color: #1a2540; }
  .stat-card.quarantine .stat-value { color: #b57a00; }
  .panel { background: #fff; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.06); margin-bottom: 1.25rem; overflow: hidden; }
  .panel-header { padding: .85rem 1.5rem; border-bottom: 1px solid #eee; font-weight: 600; font-size: 14px; display: flex; align-items: center; gap: 8px; }
  .panel-body { padding: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: .6rem 1.5rem; background: #f9f9fb; color: #555; font-weight: 500; border-bottom: 1px solid #eee; }
  td { padding: .75rem 1.5rem; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 99px; font-size: 11px; font-weight: 600; letter-spacing: .3px; }
  .badge.clean    { background: #e6f7ef; color: #1a8a5a; }
  .badge.threat   { background: #fde8e8; color: #d94040; }
  .badge.quarantined { background: #fff3cc; color: #b57a00; }
  .file-col { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 12px; }
  .hash-col { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 11px; color: #888; }
  .threat-name { color: #d94040; font-weight: 500; }
  .sig-item { display: flex; align-items: center; gap: 12px; padding: .75rem 1.5rem; border-bottom: 1px solid #f0f0f0; }
  .sig-item:last-child { border-bottom: none; }
  .sig-badge { background: #fde8e8; color: #d94040; font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 6px; flex-shrink: 0; }
  .sig-name { font-weight: 500; }
  .sig-hash { font-family: monospace; font-size: 11px; color: #888; }
  .log-entry { display: flex; gap: 12px; padding: .45rem 1.5rem; font-family: monospace; font-size: 12px; border-bottom: 1px solid #f7f7f7; }
  .log-ts { color: #aaa; flex-shrink: 0; }
  .log-entry.threat .log-msg { color: #d94040; }
  .log-entry.clean  .log-msg { color: #1a8a5a; }
  .log-entry.info   .log-msg { color: #555; }
  .bar-wrap { padding: 1rem 1.5rem; }
  .bar-label { display: flex; justify-content: space-between; font-size: 12px; color: #666; margin-bottom: 6px; }
  .bar-bg { background: #f0f0f0; border-radius: 6px; height: 10px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 6px; }
  .bar-fill.clean   { background: #1a8a5a; }
  .bar-fill.threat  { background: #d94040; }
  footer { text-align: center; color: #aaa; font-size: 12px; margin-top: 2rem; }
</style>
"""


def parse_log(log_path: str):
    results = []
    quarantined = []
    if not os.path.exists(log_path):
        return results, quarantined
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # [2024-01-01 12:00:00] CLEAN | path | hash
            try:
                ts_part, rest = line[1:].split("]", 1)
                rest = rest.strip()
                if rest.startswith("CLEAN"):
                    parts = rest.split("|")
                    results.append({"ts": ts_part, "status": "CLEAN", "file": parts[1].strip(), "hash": parts[2].strip() if len(parts) > 2 else "", "threat": ""})
                elif rest.startswith("THREAT DETECTED"):
                    parts = rest.split("|")
                    results.append({"ts": ts_part, "status": "THREAT", "file": parts[1].strip(), "threat": parts[2].strip() if len(parts) > 2 else "", "hash": parts[3].strip() if len(parts) > 3 else ""})
                elif rest.startswith("QUARANTINED"):
                    parts = rest.split("|")
                    quarantined.append(parts[1].strip() if len(parts) > 1 else rest)
            except Exception:
                pass
    return results, quarantined


def load_signatures(sig_path="signatures.json"):
    if not os.path.exists(sig_path):
        return {}
    with open(sig_path) as f:
        return json.load(f)


def generate_report(results, quarantined, signatures, output_path="report.html"):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(results)
    threats = [r for r in results if r["status"] == "THREAT"]
    clean = [r for r in results if r["status"] == "CLEAN"]
    threat_pct = round((len(threats) / total * 100) if total else 0, 1)
    clean_pct = round((len(clean) / total * 100) if total else 0, 1)

    # Build results rows
    rows_html = ""
    for r in results:
        if r["status"] == "THREAT":
            badge = '<span class="badge threat">⚠ Threat</span>'
            q_badge = '<span class="badge quarantined">quarantined</span>' if r["file"] in quarantined else ""
            tname = f'<span class="threat-name">{r["threat"]}</span>'
        else:
            badge = '<span class="badge clean">✓ Clean</span>'
            q_badge = ""
            tname = '<span style="color:#aaa">—</span>'
        h = r["hash"][:20] + "..." if len(r["hash"]) > 20 else r["hash"]
        rows_html += f"""
        <tr>
          <td class="file-col">{r["file"]} {q_badge}</td>
          <td class="hash-col">{h}</td>
          <td>{badge}</td>
          <td>{tname}</td>
          <td style="color:#aaa;font-size:12px">{r["ts"]}</td>
        </tr>"""

    # Signature rows
    sig_rows = ""
    for h, info in signatures.items():
        sig_rows += f"""
        <div class="sig-item">
          <span class="sig-badge">MALWARE</span>
          <div>
            <div class="sig-name">{info["name"]}</div>
            <div class="sig-hash">{h}</div>
          </div>
        </div>"""

    # Log rows
    log_rows = ""
    for r in results:
        cls = "threat" if r["status"] == "THREAT" else "clean"
        msg = f"THREAT DETECTED | {r['file']} | {r['threat']}" if r["status"] == "THREAT" else f"CLEAN | {r['file']}"
        log_rows += f'<div class="log-entry {cls}"><span class="log-ts">[{r["ts"]}]</span><span class="log-msg">{msg}</span></div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Antivirus Scan Report — {now}</title>
{REPORT_CSS}
</head>
<body>
<div class="wrapper">

  <header>
    <div class="shield-icon">🛡️</div>
    <div>
      <h1>Basic Antivirus Simulation — Scan Report</h1>
      <p>Generated: {now} &nbsp;|&nbsp; Engine: SHA-256 Signature Scanner &nbsp;|&nbsp; Mode: Educational</p>
    </div>
  </header>

  <div class="stats-grid">
    <div class="stat-card total">
      <div class="stat-value">{total}</div>
      <div class="stat-label">Files scanned</div>
    </div>
    <div class="stat-card clean">
      <div class="stat-value">{len(clean)}</div>
      <div class="stat-label">Clean files</div>
    </div>
    <div class="stat-card threat">
      <div class="stat-value">{len(threats)}</div>
      <div class="stat-label">Threats found</div>
    </div>
    <div class="stat-card quarantine">
      <div class="stat-value">{len(quarantined)}</div>
      <div class="stat-label">Quarantined</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">📊 Scan summary</div>
    <div class="panel-body">
      <div class="bar-wrap">
        <div class="bar-label"><span>Clean ({clean_pct}%)</span><span>{len(clean)} files</span></div>
        <div class="bar-bg"><div class="bar-fill clean" style="width:{clean_pct}%"></div></div>
      </div>
      <div class="bar-wrap">
        <div class="bar-label"><span>Threats ({threat_pct}%)</span><span>{len(threats)} files</span></div>
        <div class="bar-bg"><div class="bar-fill threat" style="width:{threat_pct}%"></div></div>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">📁 File scan results</div>
    <div class="panel-body">
      <table>
        <thead><tr><th>File</th><th>SHA-256</th><th>Status</th><th>Threat name</th><th>Scanned at</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">☣ Signature database ({len(signatures)} entries)</div>
    <div class="panel-body">{sig_rows or '<p style="padding:1rem 1.5rem;color:#aaa">No signatures loaded.</p>'}</div>
  </div>

  <div class="panel">
    <div class="panel-header">📝 Scan log</div>
    <div class="panel-body" style="max-height:300px;overflow-y:auto">{log_rows or '<p style="padding:1rem 1.5rem;color:#aaa">No log entries.</p>'}</div>
  </div>

  <footer>Basic Antivirus Simulation &mdash; Educational tool &mdash; Not for real malware detection</footer>
</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"[+] Report saved to: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate HTML scan report")
    parser.add_argument("--log",  default="scan_log.txt",  help="Path to scan_log.txt")
    parser.add_argument("--sigs", default="signatures.json", help="Path to signatures.json")
    parser.add_argument("--out",  default="report.html",    help="Output HTML file")
    args = parser.parse_args()

    results, quarantined = parse_log(args.log)
    signatures = load_signatures(args.sigs)

    if not results:
        print("[!] No log entries found. Run antivirus.py scan first, then generate the report.")
    else:
        generate_report(results, quarantined, signatures, args.out)
