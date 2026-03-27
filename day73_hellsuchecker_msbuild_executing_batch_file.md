# Name
HellsUchecker & ClickFix (EtherHiding) - MSBuild.exe Executing a Batch File

# Description
These queries are designed to identify the Tactics, Techniques, and Procedures (TTPs) associated with the HellsUchecker malware and the ClickFix/EtherHiding campaign. This detection focuses on identifying Living-off-the-Land (LotL) abuse of MSBuild.exe to execute batch files.

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
- T1218 - System Binary Proxy Execution
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell

# Data Sources
- Microsoft Defender XDR
   - DeviceProcessEvents

# Query
## Query 4: Host - MSBuild.exe Executing a Batch File

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
    // Case 1: Suspicious MSBuild execution
    datetime(2024-03-12 13:45:12), "device-guid-4", "DevStation.contoso.com", "ProcessCreated", 
    "msbuild.exe", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe", "a1b2c3d4...", 
    "msbuild.exe C:\\Users\\Public\\malicious.bat", 8832, "asmith", "CONTOSO", 
    "cmd.exe", "cmd.exe /c msbuild.exe C:\\Users\\Public\\malicious.bat", 5100, "explorer.exe"
];
// Detection Query
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where FileName =~ "msbuild.exe"
| where ProcessCommandLine has ".bat"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
