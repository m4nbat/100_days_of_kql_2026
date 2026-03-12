# Name
HellsUchecker & ClickFix (EtherHiding) - Suspicious Process Chain (msiexec -> explorer -> wscript -> cmd)

# Description
These queries are designed to identify the Tactics, Techniques, and Procedures (TTPs) associated with the HellsUchecker malware and the ClickFix/EtherHiding campaign. This detection focuses on identifying suspicious process execution chains (msiexec -> explorer -> wscript -> cmd).

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
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell
- T1059.005 - Command and Scripting Interpreter: Visual Basic
- T1218 - System Binary Proxy Execution

# Data Sources
- Microsoft Defender XDR
   - DeviceProcessEvents

# Query
## Query 3: Host - Suspicious Process Chain (msiexec -> explorer -> wscript -> cmd)

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
    // Case 1: ClickFix anomaly execution chain
    datetime(2024-03-12 12:30:00), "device-guid-3", "Laptop01.contoso.com", "ProcessCreated", 
    "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "b2c3d4e5...", 
    "cmd.exe /c start payload.exe", 6620, "jdoe", "CONTOSO", 
    "wscript.exe", "wscript.exe C:\\temp\\wscript_123.vbs", 3200, "explorer.exe"
];
// Detection Query
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where FileName =~ "cmd.exe"
| where InitiatingProcessFileName =~ "wscript.exe"
| where InitiatingProcessParentFileName =~ "explorer.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```
