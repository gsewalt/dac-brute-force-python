# 🔐 Detection-As-Code: Automated Brute Force Detection, Alert & Response in Python

This project demonstrates detection-as-code and multi-platform security integration with a Python script ([`brute_force_detector_sentinel.py`](https://github.com/gsewalt/dac-brute-force-python/blob/main/scripts/brute_force_detector_sentinel.py)) that queries **Azure Log Analytics (Microsoft Sentinel)** for failed logins, detects potential brute-force activity, and sends alerts to **Slack**.  

It also includes a safe **demo IP blocking workflow** (prints "blocked IPs list") to illustrate automated remediation.

> ⚠️ **Note:** The blocking logic is intentionally non-functional to prevent accidental disruption in production environments.

---

## ✨ Features

- Query **Microsoft Sentinel / Log Analytics** for failed login attempts  
- Detect brute-force activity (≥50 failed logins per IP in the last 24h)  
- Send summarized alerts to **Slack** via webhook  
- Save suspicious login events to CSV for further review  
- Remediation: blocks offending IPs (demo print)

---

## 📦 Requirements

- **Python** 3.10+  
- Dependencies:
  - `azure-identity`
  - `azure-monitor-query`
  - `pandas`
  - `requests`

Install them with:  

```bash
pip install azure-identity azure-monitor-query pandas requests
```

---

## ⚙️ Environment Setup

The script requires the following environment variables to be set before running:  

| Variable             | Description |
|-----------------------|-------------|
| `AZURE_WORKSPACE_ID` | The ID of your Log Analytics workspace (Microsoft Sentinel). |
| `SLACK_WEBHOOK_URL`  | Slack Incoming Webhook URL for alerts. (Optional – alerts skipped if not set). |
| Azure login variables | The script uses `DefaultAzureCredential`, which supports multiple authentication methods. Ensure you have one of the following configured:<br>• **Azure CLI login** (`az login`)<br>• **Managed Identity** (if running in Azure)<br>• **Service Principal** with environment vars: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET` |

Example (Linux/macOS):  

```bash
export AZURE_WORKSPACE_ID="your-workspace-id"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

Example (Windows PowerShell):  

```powershell
setx AZURE_WORKSPACE_ID "your-workspace-id"
setx SLACK_WEBHOOK_URL "https://hooks.slack.com/services/..."
setx AZURE_TENANT_ID "your-tenant-id"
setx AZURE_CLIENT_ID "your-client-id"
setx AZURE_CLIENT_SECRET "your-client-secret"
```

---

## 🚀 Usage

1. Set the required environment variables (see above).  

2. Run the script:  
   ```bash
   python brute_force_detector_sentinel.py
   ```

4. Output includes:  
   - Console printout of suspicious IPs with ≥50 failed logins in past 24h  
   - CSV file: `suspicious_failed_logins.csv`  
   - Slack notification (if webhook configured)  
   - Demo block messages for suspicious IPs  

---

## 📊 Example Output

**Console log:**  
```
Querying Sentinel for failed logins...

Suspicious IPs with >=50 failed logins in past 24h:
    RemoteIP    DeviceName  BruteForceAttempts
0   203.0.113.45  VM-001    72
1   203.0.113.77  VM-002    65

Results saved to suspicious_failed_logins.csv
Slack alert sent!

--- Demo: IP Block Actions ---
[DEMO] Blocking IP: 203.0.113.45
[DEMO] Blocking IP: 203.0.113.77
```

**Slack notification:**  
```
🚨 Brute-force login alerts detected:
72 failed logins from IP 203.0.113.45 on VM-001
65 failed logins from IP 203.0.113.77 on VM-002
```

---

## 🧩 Customization

- **Detection threshold:** Edit the KQL query in `sentinel_query.py` to adjust the number of failed logins or time window.  
- **Slack formatting:** Modify the `send_slack_alert()` function for richer messages (Markdown, attachments, etc.).  
- **Blocking logic:** Replace `demo_block_ips()` with calls to NSGs, firewalls, or SOAR runbooks if you want to enable real blocking.  

---

## 📄 License

MIT License © 2025 Gregory Sewalt
