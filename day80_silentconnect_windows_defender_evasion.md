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
## Query 3 - SILENTCONNECT Windows Defender Evasion
Detects PowerShell commands used to add Windows Defender exclusions, a technique heavily leveraged by SILENTCONNECT to impair defenses prior to payload execution.

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
//     // Case 1: SILENTCONNECT adding Defender exclusion
//     datetime(2026-03-27 12:00:00), "Workstation01", "ProcessCreated", "powershell.exe", "powershell.exe Add-MpPreference -ExclusionPath 'C:\\Temp'", "SYSTEM", "wscript.exe", "wscript.exe loader.vbs",
//     // Case 2: Admin adding exclusion (might trigger, needs investigation)
//     datetime(2026-03-27 12:05:00), "Workstation02", "ProcessCreated", "powershell.exe", "powershell.exe -Command Add-MpPreference -ExclusionProcess 'C:\\Dev\\tool.exe'", "admin", "explorer.exe", "explorer.exe"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where (FileName in~ ("powershell.exe", "pwsh.exe") or ProcessCommandLine has "powershell")
| where ProcessCommandLine has "Add-MpPreference" 
    and ProcessCommandLine has_any ("-ExclusionPath", "-ExclusionProcess", "-ExclusionExtension")
// Optional: Tune out known administrators or specific paths if too noisy
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
