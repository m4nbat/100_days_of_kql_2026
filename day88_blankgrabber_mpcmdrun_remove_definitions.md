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
- T1562.001: Impair Defenses: Disable or Modify Tools

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceProcessEvents

# Query
## Query 2 - Impair Defenses: MpCmdRun Remove Definitions
BlankGrabber actively tries to blind the endpoint's antivirus. This detection monitors for the execution of MpCmdRun.exe (the Microsoft Defender command-line utility) with the -RemoveDefinitions argument, a common tactic used by stealers to roll back signatures before running the primary payload.

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
//     // Case 1: BlankGrabber removing Defender definitions
//     datetime(2026-03-27 11:00:00), "Workstation01", "ProcessCreated", "MpCmdRun.exe", "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All", "SYSTEM", "python.exe", "python.exe payload.py",
//     // Case 2: Standard execution (should not trigger)
//     datetime(2026-03-27 11:05:00), "Workstation02", "ProcessCreated", "MpCmdRun.exe", "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -Scan -ScanType 1", "SYSTEM", "svchost.exe", "svchost.exe"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where FileName =~ "MpCmdRun.exe"
| where ProcessCommandLine has "-RemoveDefinitions" or ProcessCommandLine has "/RemoveDefinitions"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
