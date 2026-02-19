# Name
Radiant Spider (SilentSkimmer) - Web Shell Deployment via Certutil and Web Servers

# Description
This detection identifies web shell deployment activity associated with Radiant Spider (SilentSkimmer). It covers two vectors: the abuse of certutil.exe to decode base64-encoded ASP/ASPX files into web-accessible directories, and web server processes (e.g., w3wp.exe) directly writing ASP/ASPX files to disk. Both patterns indicate potential web shell staging on internet-facing servers.

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
- T1140: Deobfuscate/Decode Files or Information
- T1505.003: Server Software Component: Web Shell

# Data Sources
- Microsoft Defender XDR
  - DeviceProcessEvents
  - DeviceFileEvents

# Query

## Query 3: Web Shell Deployment via Certutil and Web Servers

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
    // Case 1: Certutil decoding an ASPX webshell
    datetime(2026-02-19 12:00:00), "device-guid-3", "WebSrv02.contoso.com", "ProcessCreated", 
    "certutil.exe", "C:\\Windows\\System32\\certutil.exe", "c3d4e5f6...", 
    "certutil -decode c:\\temp\\encoded.txt c:\\inetpub\\wwwroot\\shell.aspx", 1122, "DefaultAppPool", "IIS APPPOOL", 
    "cmd.exe", "cmd.exe /c certutil -decode...", 3344, "w3wp.exe"
];
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
    // Case 2: Web Server writing ASP/X file
    datetime(2026-02-19 12:05:00), "device-guid-3", "WebSrv02.contoso.com", "FileCreated", 
    "evil.aspx", "C:\\inetpub\\wwwroot\\evil.aspx", "d4e5f6a7...", 
    "DefaultAppPool", "w3wp.exe", "w3wp.exe -ap \"DefaultAppPool\""
];
// Detection Logic
// Part A: Certutil Decoding ASP/X files
let CertutilDecode = DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has "-decode" and ProcessCommandLine has_any(".asp", ".aspx")
| project Timestamp, DeviceName, EventType = "Certutil Decode", FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName;
// Part B: Web servers writing ASP/X
let WebServerWrite = DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("w3wp.exe", "tomcat.exe", "coldfusion.exe", "jrun.exe")
| where FileName endswith ".asp" or FileName endswith ".aspx"
| where FolderPath !has "Temporary ASP.NET Files"
| project Timestamp, DeviceName, EventType = "Webserver File Write", FileName = InitiatingProcessFileName, ProcessCommandLine = InitiatingProcessCommandLine, InitiatingProcessFileName = "", AccountName = InitiatingProcessAccountName;
// Combine the results
CertutilDecode
| union WebServerWrite
```
