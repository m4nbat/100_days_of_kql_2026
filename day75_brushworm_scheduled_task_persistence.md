# Name
BRUSHWORM and BRUSHLOGGER Persistence, Staging, and C2 Activity

# Description
This detection identifies additional indicators of compromise (IOCs) from the Elastic Security Labs report on BRUSHWORM and BRUSHLOGGER. These secondary behaviors include the creation of specific scheduled tasks (MSGraphics and MSRecorder) used for persistence and execution of the side-loaded DLLs. It also detects the unique data staging directory (C:\Users\Public\Systeminfo\) and the exfiltration hash tracking file (hashconfig in the NuGet directory). Finally, it includes a network query to identify communication with the known command-and-control (C2) server and the specific URI used to download the DLL payload (/updtdll).

# References
- https://www.elastic.co/security-labs/brushworm-targets-financial-services

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- BRUSHWORM (Backdoor / Worm)
- BRUSHLOGGER (Keylogger)

# MITRE ATT&CK
- T1053.005: Scheduled Task/Job: Scheduled Task
- T1074.001: Data Staged: Local Data Staging
- T1071.001: Application Layer Protocol: Web Protocols
- T1574.002: Hijack Execution Flow: DLL Side-Loading

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceProcessEvents

# Query
## Query 1 - BRUSHWORM Scheduled Task Persistence
This query monitors for the creation of the specific scheduled tasks MSGraphics (used for the main backdoor persistence) and MSRecorder (used to execute the side-loaded Recorder.dll).

```kql
// let DeviceProcessEvents = datatable(
//     Timestamp: datetime,
//     DeviceId: string,
//     DeviceName: string,
//     ActionType: string,
//     FileName: string,
//     FolderPath: string,
//     ProcessCommandLine: string,
//     AccountName: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string
// )
// [
//     // Case 1: BRUSHWORM primary persistence task
//     datetime(2026-03-27 10:00:00), "device-guid-1", "Finance-WKST1", "ProcessCreated", "schtasks.exe", @"C:\Windows\System32\schtasks.exe", "schtasks.exe /create /tn MSGraphics /tr C:\\ProgramData\\Photoes\\Pics\\brushworm.exe /sc onlogon", "SYSTEM", "brushworm.exe", "brushworm.exe",
//     // Case 2: BRUSHLOGGER execution task
//     datetime(2026-03-27 10:05:00), "device-guid-2", "Finance-WKST2", "ProcessCreated", "schtasks.exe", @"C:\Windows\System32\schtasks.exe", "schtasks.exe /create /tn MSRecorder /tr \"rundll32.exe C:\\Users\\Public\\Libraries\\Recorder.dll,EntryPoint\" /sc onlogon", "SYSTEM", "brushworm.exe", "brushworm.exe",
//     // Case 3: Normal baseline activity (should not trigger)
//     datetime(2026-03-27 10:15:00), "device-guid-3", "Finance-WKST3", "ProcessCreated", "schtasks.exe", @"C:\Windows\System32\schtasks.exe", "schtasks.exe /create /tn GoogleUpdate /tr update.exe /sc daily", "jdoe", "cmd.exe", "cmd.exe /c schtasks.exe"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d) // Filter early for performance
| where ActionType == "ProcessCreated"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "MSGraphics" or ProcessCommandLine has "MSRecorder"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
