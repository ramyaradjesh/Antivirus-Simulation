"""
email_alert.py — Email Alert System

Automatically sends you an email when a threat is detected.
Uses Python's built-in smtplib — no extra install needed.

Setup (one time only):
  1. Use a Gmail account
  2. Go to: Google Account → Security → 2-Step Verification → App Passwords
  3. Create an App Password for "Mail"
  4. Paste it below as EMAIL_APP_PASSWORD
  5. Set your Gmail address as EMAIL_SENDER
  6. Set where alerts go as EMAIL_RECEIVER (can be same address)
"""

import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Config — fill these in ────────────────────────────────────────────────────
EMAIL_SENDER       = "your_gmail@gmail.com"       # your Gmail address
EMAIL_APP_PASSWORD = "PASTE_APP_PASSWORD_HERE"    # Gmail App Password (not your real password)
EMAIL_RECEIVER     = "your_gmail@gmail.com"       # where to send alerts (can be same)
EMAIL_ENABLED      = False                        # set to True once you fill in above


def send_threat_alert(filepath: str, threat_name: str, detection_source: str, file_hash: str = None):
    """
    Send an email alert when a THREAT is detected.

    Parameters:
      filepath         — full path of the detected file
      threat_name      — name of the threat e.g. Trojan.Dropper.Alpha
      detection_source — "local", "virustotal", or "heuristic"
      file_hash        — SHA-256 hash of the file (optional)
    """
    if not EMAIL_ENABLED:
        print("[!] Email alerts disabled. Fill in email_alert.py config to enable.")
        return False

    if EMAIL_APP_PASSWORD == "PASTE_APP_PASSWORD_HERE":
        print("[!] Email App Password not set in email_alert.py")
        return False

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename  = filepath.split("\\")[-1].split("/")[-1]

    # Source label for the email
    source_labels = {
        "local":      "Local Signature Database (Layer 1)",
        "virustotal": "VirusTotal Cloud Intelligence (Layer 2)",
        "heuristic":  "Heuristic Detection Engine (Layer 3)",
    }
    source_label = source_labels.get(detection_source, detection_source)

    # ── Build the email ───────────────────────────────────────────────────────
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[MyAV ALERT] Threat Detected: {filename}"
    msg["From"]    = EMAIL_SENDER
    msg["To"]      = EMAIL_RECEIVER

    # Plain text version
    plain_text = f"""
MyAV — Threat Detection Alert
==============================

A threat was detected on your system.

File     : {filepath}
Threat   : {threat_name}
Source   : {source_label}
Time     : {timestamp}
Hash     : {file_hash or 'N/A'}

The file has been flagged. If quarantine was enabled,
it has been moved to your quarantine folder.

-------------------------------
MyAV Basic Antivirus Simulation
Educational Project
"""

    # HTML version (nicer in email clients)
    html_text = f"""
<html>
<body style="font-family: Arial, sans-serif; background: #f4f5f7; padding: 20px;">
  <div style="max-width: 500px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">

    <div style="background: #1a2540; padding: 24px; text-align: center;">
      <div style="font-size: 40px;">🛡️</div>
      <h1 style="color: white; margin: 8px 0 4px; font-size: 20px;">Threat Detected</h1>
      <p style="color: #94a3b8; margin: 0; font-size: 13px;">MyAV Security Alert</p>
    </div>

    <div style="padding: 24px;">
      <div style="background: #fee2e2; border: 1px solid #fca5a5; border-radius: 8px; padding: 16px; margin-bottom: 20px;">
        <p style="color: #dc2626; font-weight: bold; margin: 0 0 4px;">⚠️ {threat_name}</p>
        <p style="color: #991b1b; font-size: 13px; margin: 0;">Detected by {source_label}</p>
      </div>

      <table style="width: 100%; font-size: 13px; border-collapse: collapse;">
        <tr style="border-bottom: 1px solid #f0f0f0;">
          <td style="padding: 10px 0; color: #6b7280; width: 80px;">File</td>
          <td style="padding: 10px 0; font-family: monospace; color: #1a1a1a;">{filename}</td>
        </tr>
        <tr style="border-bottom: 1px solid #f0f0f0;">
          <td style="padding: 10px 0; color: #6b7280;">Path</td>
          <td style="padding: 10px 0; font-family: monospace; font-size: 11px; color: #6b7280;">{filepath}</td>
        </tr>
        <tr style="border-bottom: 1px solid #f0f0f0;">
          <td style="padding: 10px 0; color: #6b7280;">Time</td>
          <td style="padding: 10px 0;">{timestamp}</td>
        </tr>
        <tr style="border-bottom: 1px solid #f0f0f0;">
          <td style="padding: 10px 0; color: #6b7280;">Source</td>
          <td style="padding: 10px 0;">{source_label}</td>
        </tr>
        <tr>
          <td style="padding: 10px 0; color: #6b7280;">Hash</td>
          <td style="padding: 10px 0; font-family: monospace; font-size: 11px; color: #6b7280;">{file_hash or 'N/A'}</td>
        </tr>
      </table>
    </div>

    <div style="background: #f9fafb; padding: 16px; text-align: center; font-size: 12px; color: #9ca3af;">
      MyAV Basic Antivirus Simulation — Educational Project
    </div>
  </div>
</body>
</html>
"""

    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_text,  "html"))

    # ── Send via Gmail SMTP ───────────────────────────────────────────────────
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_APP_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print(f"[+] Email alert sent to {EMAIL_RECEIVER}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("[!] Email failed: Wrong Gmail address or App Password.")
        print("    Make sure you are using an App Password, not your real Gmail password.")
        return False

    except Exception as e:
        print(f"[!] Email failed: {e}")
        return False


def send_suspicious_alert(filepath: str, findings: list):
    """
    Send an email alert when a SUSPICIOUS file is detected by heuristics.
    Less urgent than a threat alert — uses a warning tone.
    """
    if not EMAIL_ENABLED:
        return False

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename  = filepath.split("\\")[-1].split("/")[-1]
    findings_text = "\n".join(f"  - {f['reason']}" for f in findings)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[MyAV WARNING] Suspicious File: {filename}"
    msg["From"]    = EMAIL_SENDER
    msg["To"]      = EMAIL_RECEIVER

    plain_text = f"""
MyAV — Suspicious File Warning
================================

A suspicious file was detected by heuristic analysis.

File     : {filepath}
Time     : {timestamp}

Heuristic findings:
{findings_text}

This file was NOT confirmed as malware but shows suspicious
characteristics. Review it manually before opening.

-------------------------------
MyAV Basic Antivirus Simulation
"""

    msg.attach(MIMEText(plain_text, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_APP_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print(f"[+] Suspicious file alert sent to {EMAIL_RECEIVER}")
        return True
    except Exception as e:
        print(f"[!] Email failed: {e}")
        return False


# ── Quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Email alert module loaded.")
    print(f"  Enabled  : {EMAIL_ENABLED}")
    print(f"  Sender   : {EMAIL_SENDER}")
    print(f"  Receiver : {EMAIL_RECEIVER}")
    if not EMAIL_ENABLED:
        print("\n  To enable: fill in EMAIL_SENDER, EMAIL_APP_PASSWORD, EMAIL_RECEIVER")
        print("  then set EMAIL_ENABLED = True")
