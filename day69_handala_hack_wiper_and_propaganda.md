# Name
Handala Hack (Void Manticore) - Wiper Batch Script Execution and Propaganda Image Drop

# Description
These queries are designed to identify the Tactics, Techniques, and Procedures (TTPs) associated with Handala Hack (also known as Void Manticore), an Iranian MOIS-affiliated threat actor. These detections focus on identifying the execution of their custom wiper batch script `handala.bat` via Group Policy, and the creation of their signature propaganda image `handala.gif` across logical drives.

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
- T1485 - Data Destruction

# Data Sources
- Microsoft Defender XDR
   - DeviceProcessEvents
   - DeviceFileEvents

# Query
## Query 3: Handala Hack - Wiper Execution via Batch Script

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
    // Case 1: Wiper trigger via Group Policy distributed script
    datetime(2026-03-12 11:00:00), "device-guid-4", "Server01.contoso.com", "ProcessCreated", 
    "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "b2c3d4e5...", 
    "cmd.exe /c \"C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Startup\\handala.bat\"", 6620, "SYSTEM", "NT AUTHORITY", 
    "svchost.exe", "svchost.exe -k netsvcs", 3200, "services.exe"
];
// Detection Query
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has "handala.bat" or FileName =~ "handala.bat"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Query 4: Handala Hack - Propaganda Image Dropped

```kql
// Let statement for testing the query logic
let DeviceFileEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    ActionType: string,
    FileName: string,
    FolderPath: string,
    SHA256: string,
    InitiatingProcessAccountDomain: string,
    InitiatingProcessAccountName: string,
    InitiatingProcessCommandLine: string,
    InitiatingProcessFileName: string
)
[
    // Case 1: Propaganda image file creation
    datetime(2026-03-12 11:05:00), "device-guid-5", "Server01.contoso.com", "FileCreated", 
    "handala.gif", "C:\\Users\\handala.gif", "c3d4e5f6...", 
    "NT AUTHORITY", "SYSTEM", "powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\wiper.ps1", "powershell.exe"
];
// Detection Query
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType == "FileCreated"
| where FileName =~ "handala.gif"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
