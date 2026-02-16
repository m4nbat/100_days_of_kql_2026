# Name
Suspicious Service Stopping via SC.exe (Prometei Behavior)

# Description
This detection identifies the suspicious stopping and disabling of the WinRM (Windows Remote Management) service using the sc.exe command. This behavior was highlighted in the analysis of the Prometei botnet (as well as other ransomware/wipers) which disables remote administration capabilities to hinder incident response and remediation efforts.

The detection looks for sc.exe stopping a service (specifically winrm) and subsequently configuring it to disabled.

# References
- https://www.knowyouradversary.ru/2026/02/374-hunting-for-suspicious-service.html
- https://attack.mitre.org/techniques/T1489/ (Service Stop)

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Prometei Botnet
- Ransomware (General)
- Wipers

# MITRE ATT&CK
- T1489 (Service Stop)
- T1562.001 (Impair Defenses: Disable or Modify Tools)

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents
- Microsoft Sentinel
  - SecurityEvent (Event ID 4688)

# Query

## Query 1: Suspicious Service Stop and Disable (Defender)
This query searches for process execution events where sc.exe is used to targeting the winrm service, specifically looking for stop or disabled arguments in the command line.

```kql
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
    // Case 1: Prometei Behavior - Stopping WinRM
    datetime(2026-02-15 14:30:00), "device-guid-1", "Server01.contoso.com", "ProcessCreated", 
    "sc.exe", "C:\\Windows\\System32\\sc.exe", "e3b0c442...", 
    "sc stop WinRM", 4120, "SYSTEM", "NT AUTHORITY", 
    "cmd.exe", "cmd.exe", 680, "services.exe",

    // Case 2: Prometei Behavior - Disabling WinRM
    datetime(2026-02-15 14:30:05), "device-guid-1", "Server01.contoso.com", "ProcessCreated", 
    "sc.exe", "C:\\Windows\\System32\\sc.exe", "a5b3c2d1...", 
    "sc config WinRM start= disabled", 4122, "SYSTEM", "NT AUTHORITY", 
    "cmd.exe", "cmd.exe", 680, "services.exe",

    // Case 3: Legitimate Admin Activity (different service)
    datetime(2026-02-15 09:00:00), "device-guid-2", "AdminWorkstation.contoso.com", "ProcessCreated", 
    "sc.exe", "C:\\Windows\\System32\\sc.exe", "b2c3d4e5...", 
    "sc stop Spooler", 6620, "admin_user", "CONTOSO", 
    "powershell.exe", "powershell.exe", 3200, "explorer.exe"
];
// Usage: Run detection against DeviceProcessEvents
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has "WinRM" 
| where (ProcessCommandLine has "stop" or ProcessCommandLine has "disabled")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Query 2: Suspicious Service Stop and Disable (Sentinel)
Equivalent query for Microsoft Sentinel using SecurityEvent.

```kql
// Define a dummy table for testing
let SecurityEvent = datatable(
    TimeGenerated: datetime,
    Computer: string,
    EventID: int,
    CommandLine: string,
    SubjectUserName: string,
    ParentProcessName: string,
    NewProcessName: string
)
[
    // Case 1: Prometei Behavior
    datetime(2026-02-15 14:30:00), "Server01.contoso.com", 4688, 
    "sc stop WinRM", "SYSTEM", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\sc.exe"
];
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4688
| where CommandLine has "sc.exe" or NewProcessName has "sc.exe"
| where CommandLine has "WinRM" 
| where (CommandLine has "stop" or CommandLine has "disabled")
| project TimeGenerated, Computer, CommandLine, SubjectUserName, ParentProcessName
```
