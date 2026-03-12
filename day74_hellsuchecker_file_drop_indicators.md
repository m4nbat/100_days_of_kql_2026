# Name
HellsUchecker & ClickFix (EtherHiding) - File Drop Indicators

# Description
These queries are designed to identify the Tactics, Techniques, and Procedures (TTPs) associated with the HellsUchecker malware and the ClickFix/EtherHiding campaign. This detection focuses on identifying specific file drop indicators including the `SvcUpdate_` folder pattern and `wscript_*.vbs`/`runtime_*.cache` file naming conventions.

# References
- https://www.derp.ca/research/hellsuchecker-clickfix-etherhiding/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- HellsUchecker
- ClickFix
- EtherHiding

# MITRE ATT&CK
- T1105 - Ingress Tool Transfer
- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

# Data Sources
- Microsoft Defender XDR
   - DeviceFileEvents

# Query
## Query 5: Host - HellsUchecker File Drop Indicators

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
    // Case 1: Suspicious folder path creation (SvcUpdate_8d52)
    datetime(2024-03-12 14:05:00), "device-guid-5", "Server01.contoso.com", "FileCreated", 
    "payload.exe", "C:\\Users\\Public\\SvcUpdate_8d52\\payload.exe", "c3d4e5f6...", 
    "NT AUTHORITY", "SYSTEM", "msiexec.exe /i update.msi /qn", "msiexec.exe",

    // Case 2: Suspicious wscript script drop
    datetime(2024-03-12 14:10:00), "device-guid-5", "Server01.contoso.com", "FileCreated", 
    "wscript_9928.vbs", "C:\\Users\\Public\\wscript_9928.vbs", "d4e5f6g7...", 
    "NT AUTHORITY", "SYSTEM", "msiexec.exe /i update.msi /qn", "msiexec.exe"
];
// Detection Query
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has "SvcUpdate_" 
    or FileName matches regex @"(?i)^wscript_.*\.bat$" 
    or FileName matches regex @"(?i)^wscript_.*\.vbs$" 
    or FileName matches regex @"(?i)^runtime_.*\.cache$"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
