# Name
Radiant Spider (SilentSkimmer) Initial Access and Web Shell Activity - ASPX Web Shell Creation by Web Server Processes

# Description
This detection identifies the deployment of .aspx web shells by the RADIANT SPIDER threat actor. It detects when web server processes (IIS, ColdFusion) create .aspx or .ashx files outside of typical compiled ASP.NET temporary directories, indicating potential web shell installation following initial compromise.

**Detection Engineer Notes:** RADIANT SPIDER employs a custom Golang loader that aggressively rewrites its configuration in memory. Because it bypasses hash-based IOC lists, network telemetry (beaconing to unknown IPs from unexpected processes like w3wp.exe) and behavioral tracking via DeviceNetworkEvents should be paired with the process creation detections above.

# References
- https://www.crowdstrike.com/adversaries/radiant-spider/
- https://www.sleuthcon.com/radiant-spider-unveiled

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
- T1190: Exploit Public-Facing Application
- T1505.003: Server Software Component: Web Shell
- T1059.001: Command and Scripting Interpreter: PowerShell
- T1056.003: Input Capture: Web Portal Capture (Formjacking)

# Data Sources
- Microsoft Defender XDR (Advanced Hunting)
  - DeviceFileEvents

# Query

## Query 2: ASPX Web Shell Creation by Web Server Processes

```kql
// Test Data Table
let DeviceFileEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    ActionType: string,
    FileName: string,
    FolderPath: string,
    SHA256: string,
    InitiatingProcessAccountName: string,
    InitiatingProcessFileName: string,
    InitiatingProcessCommandLine: string
)
[
    // Case 1: Suspicious ASPX file drop
    datetime(2026-02-19 14:00:00), "device-guid-1", "WebSrv01.contoso.com", "FileCreated", 
    "update_log.aspx", "C:\\inetpub\\wwwroot\\update_log.aspx", "c3d4e5f6...", 
    "DefaultAppPool", "w3wp.exe", "w3wp.exe -ap \"DefaultAppPool\"",

    // Case 2: Normal log creation
    datetime(2026-02-19 14:05:00), "device-guid-1", "WebSrv01.contoso.com", "FileCreated", 
    "trace.log", "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\trace.log", "d4e5f6a7...", 
    "DefaultAppPool", "w3wp.exe", "w3wp.exe -ap \"DefaultAppPool\""
];
// Detection Logic
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType == "FileCreated"
// Filter early for web server application pools/services
| where InitiatingProcessFileName in~ ("w3wp.exe", "jrun.exe", "coldfusion.exe")
// Identify specific file extensions utilized by Radiant Spider for web shells
| where FileName endswith ".aspx" or FileName endswith ".ashx"
// Exclude typical compiled ASP.NET temporary directories to reduce noise
| where FolderPath !has "Temporary ASP.NET Files"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName
```
