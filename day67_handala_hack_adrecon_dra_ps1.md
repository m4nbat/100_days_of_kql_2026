# Name
Handala Hack (Void Manticore) - ADRecon Execution via dra.ps1

# Description
These queries are designed to identify the Tactics, Techniques, and Procedures (TTPs) associated with Handala Hack (also known as Void Manticore), an Iranian MOIS-affiliated threat actor. This detection focuses on identifying the execution of ADRecon renamed as `dra.ps1` for Active Directory enumeration.

# References
- https://research.checkpoint.com/2026/handala-hack-unveiling-groups-modus-operandi/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Handala Hack
- Void Manticore
- Red Sandstorm
- Banished Kitten
- Homeland Justice

# MITRE ATT&CK
- T1087.002 - Account Discovery: Domain Account

# Data Sources
- Microsoft Defender XDR
   - DeviceProcessEvents

# Query
## Query 1: Handala Hack - ADRecon Execution (dra.ps1)

```kql
// Let statement for testing the query logic
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
    // Case 1: Suspicious ADRecon execution matching Handala Hack TTPs
    datetime(2026-03-12 10:15:30), "device-guid-1", "DC01.contoso.com", "ProcessCreated", 
    "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "a5b3c2d1...", 
    "powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\dra.ps1", 8832, "admin", "CONTOSO", 
    "cmd.exe", "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\dra.ps1", 5100, "explorer.exe",
    
    // Case 2: Standard benign process
    datetime(2026-03-12 10:20:00), "device-guid-2", "Workstation01.contoso.com", "ProcessCreated", 
    "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "e3b0c442...", 
    "svchost.exe -k netsvcs -p", 4120, "SYSTEM", "NT AUTHORITY", 
    "services.exe", "services.exe", 680, "wininit.exe"
];
// Detection Query
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has "dra.ps1"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
