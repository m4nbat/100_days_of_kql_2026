# Name
SILENTCONNECT Loader and ScreenConnect Deployment

# Description
This detection suite identifies indicators of compromise (IOCs) and behaviors associated with SILENTCONNECT, a multi-stage loader designed to silently deploy the ConnectWise ScreenConnect Remote Monitoring and Management (RMM) tool. The threat actors utilize social engineering lures (VBScripts), PowerShell for in-memory execution, and PEB masquerading.

# References
- https://www.elastic.co/security-labs/silentconnect-delivers-screenconnect

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- SILENTCONNECT (Multi-stage Loader)
- ScreenConnect (Abused Legitimate RMM Tool)

# MITRE ATT&CK
- T1059.005: Command and Scripting Interpreter: Visual Basic
- T1059.001: Command and Scripting Interpreter: PowerShell
- T1562.001: Impair Defenses: Disable or Modify Tools
- T1219: Remote Access Software
- T1105: Ingress Tool Transfer

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceProcessEvents

# Query
## Query 1 - SILENTCONNECT VBScript Lure Execution
Detects the execution of known VBScript file names associated with the SILENTCONNECT campaigns to gain initial access.

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
//     // Case 1: SILENTCONNECT VBS execution
//     datetime(2026-03-27 10:00:00), "Workstation01", "ProcessCreated", "wscript.exe", "wscript.exe \"C:\\Users\\victim\\Downloads\\Alaska Airlines 2026 Fleet & Route Expansion Summary.vbs\"", "victim", "explorer.exe", "explorer.exe",
//     // Case 2: Another known lure
//     datetime(2026-03-27 10:05:00), "Workstation02", "ProcessCreated", "cscript.exe", "cscript.exe \"C:\\Users\\victim\\Desktop\\Proposal-03-2026.vbs\"", "victim", "explorer.exe", "explorer.exe",
//     // Case 3: Legitimate script execution (should not trigger)
//     datetime(2026-03-27 10:10:00), "Workstation03", "ProcessCreated", "wscript.exe", "wscript.exe logon.vbs", "jdoe", "cmd.exe", "cmd.exe /c logon.vbs"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine has_any (
    "Alaska Airlines 2026 Fleet & Route Expansion Summary.vbs",
    "CODE7_ZOOMCALANDER_INSTALLER_4740.vbs",
    "2025Trans.vbs",
    "Proposal-03-2026.vbs",
    "updatv35.vbs"
)
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
