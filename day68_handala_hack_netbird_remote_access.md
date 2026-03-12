# Name
Handala Hack (Void Manticore) - NetBird Remote Access Tool Execution

# Description
These queries are designed to identify the Tactics, Techniques, and Procedures (TTPs) associated with Handala Hack (also known as Void Manticore), an Iranian MOIS-affiliated threat actor. This detection focuses on identifying the unauthorized installation of the NetBird remote access tool to establish internal connectivity.

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
- T1133 - External Remote Services
- T1569.002 - System Services: Service Execution

# Data Sources
- Microsoft Defender XDR
   - DeviceProcessEvents

# Query
## Query 2: Handala Hack - NetBird Remote Access Tool Execution

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
    // Case 1: Unauthorized NetBird execution
    datetime(2026-03-12 12:05:00), "device-guid-3", "Server02.contoso.com", "ProcessCreated", 
    "netbird.exe", "C:\\Program Files\\NetBird\\netbird.exe", "d4e5f6g7...", 
    "\"C:\\Program Files\\NetBird\\netbird.exe\" up", 4432, "admin", "CONTOSO", 
    "cmd.exe", "cmd.exe /c \"C:\\Program Files\\NetBird\\netbird.exe\" up", 5120, "explorer.exe"
];
// Detection Query
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where FileName =~ "netbird.exe" or ProcessCommandLine has "netbird.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
