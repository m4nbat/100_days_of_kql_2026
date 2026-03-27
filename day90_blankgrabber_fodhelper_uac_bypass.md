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
- T1548.002: Abuse Elevation Control Mechanism: Bypass User Account Control

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceProcessEvents

# Query
## Query 4 - UAC Bypass via Fodhelper Execution
To effectively steal data across the entire system and modify registry settings like Defender configurations, BlankGrabber needs elevated privileges. This detection identifies the abuse of the fodhelper.exe UAC bypass, looking for the anomalous behavior of fodhelper.exe acting as a parent process to command shells or the Python interpreter.

```kql
// let DeviceProcessEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     FileName: string,
//     ProcessCommandLine: string,
//     AccountName: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string
// )
// [
//     // Case 1: Fodhelper spawning Python (BlankGrabber elevated)
//     datetime(2026-03-27 13:00:00), "Workstation01", "ProcessCreated", "pythonw.exe", "pythonw.exe payload.pyc", "victim", "fodhelper.exe", "fodhelper.exe",
//     // Case 2: Fodhelper spawning command prompt
//     datetime(2026-03-27 13:05:00), "Workstation02", "ProcessCreated", "cmd.exe", "cmd.exe /c start payload.exe", "victim", "fodhelper.exe", "fodhelper.exe",
//     // Case 3: Standard app execution (should not trigger)
//     datetime(2026-03-27 13:10:00), "Workstation03", "ProcessCreated", "notepad.exe", "notepad.exe", "jdoe", "explorer.exe", "explorer.exe"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName =~ "fodhelper.exe"
// Look for common execution engines or payloads being spawned from the hijacked UAC binary
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "python.exe", "pythonw.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
