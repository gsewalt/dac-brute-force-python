# ============================================================
#  Script Name: Azure Sentinel Brute Force Detector
#  Description: Detects brute force attempts from Sentinel logs,
#               sends alerts to Slack, and includes a demo
#               workflow for blocking malicious IPs.
#
#  Version:     1.0
#  Author:      Gregory Sewalt
#  Tested On:   Python 3.10+, Azure Sentinel, Slack API
#  Dependencies: requests, azure-identity, azure-monitor-query
#
#  Notes: 
#    - Blocking functionality is provided as a demo only.
#      It is intentionally non-functional to prevent
#      accidental disruption in production environments.
#    - Customize Slack webhook and Sentinel query as needed.
#
#  License: MIT
#  Copyright (c) 2025 Gregory Sewalt
# ============================================================
# Prereqs: pip install azure-identity azure-monitor-query pandas requests
# Set environment variables:
#   AZURE_WORKSPACE_ID=<workspace-id>
#   SLACK_WEBHOOK_URL=<your-slack-webhook-url>

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
import pandas as pd
import os
from datetime import timedelta
import requests

# ------------------------------
# CONFIGURATION
# ------------------------------
WORKSPACE_ID = os.environ.get("AZURE_WORKSPACE_ID")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

if not WORKSPACE_ID:
    raise ValueError("Set AZURE_WORKSPACE_ID as an environment variable.")

if not SLACK_WEBHOOK_URL:
    print("Warning: SLACK_WEBHOOK_URL not set. Slack alerts will not be sent.")

# KQL Query: detect IPs with 50+ failed logins in the past 24 hours
KQL_QUERY = """
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| where TimeGenerated >= ago(24h)
| summarize BruteForceAttempts = count() by RemoteIP, DeviceName
| where BruteForceAttempts >= 50
"""

# ------------------------------
# FUNCTION: run_kql
# ------------------------------
def run_kql(query, workspace_id=WORKSPACE_ID, timespan=timedelta(days=1)):
    """
    Run a KQL query against the given Log Analytics workspace.
    Returns a pandas DataFrame of results.
    """
    credential = DefaultAzureCredential()
    client = LogsQueryClient(credential)

    response = client.query_workspace(workspace_id, query, timespan=timespan)

    if response.status == LogsQueryStatus.PARTIAL:
        print("Partial results returned (some tables failed)")
        tables = response.partial_data
    elif response.status == LogsQueryStatus.SUCCESS:
        tables = response.tables
    else:
        raise Exception("Query failed")

    if not tables:
        print("No results found.")
        return pd.DataFrame()

    table = tables[0]
    df = pd.DataFrame(data=table.rows, columns=table.columns)
    return df

# ------------------------------
# FUNCTION: send_slack_alert
# ------------------------------
def send_slack_alert(df):
    """
    Send all suspicious login attempts in a single Slack message.
    """
    if SLACK_WEBHOOK_URL is None or df.empty:
        return

    message_lines = ["🚨 Brute-force login alerts detected:"]
    for _, row in df.iterrows():
        ip = row["RemoteIP"]
        device = row["DeviceName"]
        attempts = row["BruteForceAttempts"]
        message_lines.append(f"{attempts} failed logins from IP {ip} on {device}")

    message_text = "\n".join(message_lines)

    response = requests.post(SLACK_WEBHOOK_URL, json={"text": message_text})
    if response.status_code != 200:
        print(f"Slack alert failed: {response.status_code}, {response.text}")

# ------------------------------
# FUNCTION: demo_block_ips
# ------------------------------
def demo_block_ips(df):
    """
    Demo IP block logic. Simply prints the IPs in a clean, uniform format.
    """
    if df.empty:
        return

    print("\n--- Demo: IP Block Actions ---")
    for ip in df["RemoteIP"]:
        print(f"[DEMO] Blocking IP: {ip}")

# ------------------------------
# MAIN SCRIPT
# ------------------------------
def main():
    print("Querying Sentinel for failed logins...")
    try:
        df = run_kql(KQL_QUERY)
    except Exception as e:
        print("Error querying workspace:", e)
        return

    if df.empty:
        print("No suspicious IPs detected.")
        return

    print("\nSuspicious IPs with >=50 failed logins in past 24h:")
    print(df)

    # Optional: save results to CSV for review or demo
    df.to_csv("suspicious_failed_logins.csv", index=False)
    print("\nResults saved to suspicious_failed_logins.csv")

    # Send Slack alert
    send_slack_alert(df)
    print("Slack alert sent!")

    # Demo IP block
    demo_block_ips(df)

if __name__ == "__main__":
    main()

