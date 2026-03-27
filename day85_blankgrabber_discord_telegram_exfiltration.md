# Name
BlankGrabber Info Stealer Execution and C2 Activity

# Description
This detection suite identifies indicators of compromise (IOCs) and behaviors associated with BlankGrabber, a Python-based information stealer. BlankGrabber is engineered to exfiltrate sensitive data such as browser credentials, session tokens, and cryptocurrency wallets. It is often compiled into a standalone executable using PyInstaller to evade static detection.

# References
- https://www.splunk.com/en_us/blog/security/blankgrabber-trojan-stealer-analysis-detection.html

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- BlankGrabber (Information Stealer / Trojan)

# MITRE ATT&CK
- T1027: Obfuscated Files or Information
- T1071.001: Application Layer Protocol: Web Protocols
- T1552.001: Credentials In Files
- T1059.006: Command and Scripting Interpreter: Python

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceNetworkEvents

# Query
## Query 2 - BlankGrabber Exfiltration via Discord or Telegram API
BlankGrabber frequently abuses legitimate messaging platforms like Discord (via Webhooks) or Telegram (via Bot APIs) to exfiltrate stolen credentials and system data. This query hunts for successful connections or DNS requests to these APIs originating from suspicious or non-standard executables (excluding typical web browsers).

```kql
// let DeviceNetworkEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     RemoteIP: string,
//     RemoteUrl: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string,
//     InitiatingProcessAccountName: string
// )
// [
//     // Case 1: BlankGrabber exfiltrating via Telegram Bot API
//     datetime(2026-03-27 11:00:00), "Workstation01", "ConnectionSuccess", "149.154.167.220", "api.telegram.org", "update_utility.exe", "update_utility.exe", "victim",
//     // Case 2: BlankGrabber exfiltrating via Discord Webhooks
//     datetime(2026-03-27 11:05:00), "Workstation02", "HttpConnectionInspected", "162.159.135.232", "discord.com/api/webhooks/...", "python.exe", "python.exe payload.py", "victim",
//     // Case 3: Legitimate user browsing Discord (should not trigger)
//     datetime(2026-03-27 11:10:00), "Workstation03", "ConnectionSuccess", "162.159.135.232", "discord.com", "chrome.exe", "chrome.exe", "jdoe"
// ];
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType in~ ("ConnectionSuccess", "HttpConnectionInspected", "DnsConnectionInspected")
// Target Telegram API and Discord Webhook endpoints
| where RemoteUrl has_any ("api.telegram.org", "discord.com/api/webhooks")
// Exclude common browsers and official chat clients to reduce false positives
| where InitiatingProcessFileName !in~ (
    "chrome.exe", 
    "msedge.exe", 
    "firefox.exe", 
    "brave.exe", 
    "opera.exe", 
    "discord.exe", 
    "telegram.exe",
    "iexplore.exe"
)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
