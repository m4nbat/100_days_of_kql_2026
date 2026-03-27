# Name
BRUSHWORM and BRUSHLOGGER Activity - Process Execution from Anomalous Paths

# Description
This detection identifies indicators of compromise (IOCs) associated with the BRUSHWORM and BRUSHLOGGER malware, newly identified custom malware components observed targeting financial institutions. BRUSHWORM acts as a modular backdoor and worm that propagates via USB removable media using socially engineered filenames (e.g., Salary Slips.exe). It installs itself into a misspelled directory C:\ProgramData\Photoes\Pics\ and stores an encrypted configuration file in a non-standard public profile path C:\Users\Public\AppData\Roaming\Microsoft\Vault\keyE.dat. BRUSHLOGGER is a complementary DLL-side-loaded keylogger used for stealing credentials and keystrokes.

This query identifies if any process executes from the misspelled "Photoes" directory, indicating active execution of the BRUSHWORM backdoor.

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
- T1091 - Replication Through Removable Media
- T1053.005 - Scheduled Task/Job: Scheduled Task
- T1574.002 - Hijack Execution Flow: DLL Side-Loading
- T1056.001 - Input Capture: Keylogging
- T1074.001 - Data Staged: Local Data Staging

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
  - DeviceProcessEvents

# Query
## Query 2: BRUSHWORM Process Execution from Anomalous Paths

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
//     // Case 1: Execution of BRUSHWORM payload
//     datetime(2026-03-27 11:00:00), "device-guid-1", "Finance-WKST1", "ProcessCreated", "brushworm.exe", @"C:\ProgramData\Photoes\Pics\brushworm.exe", "brushworm.exe", "SYSTEM", "schtasks.exe", "schtasks.exe /run /tn MicrosoftUpdate",
//     // Case 2: Standard execution (should not trigger)
//     datetime(2026-03-27 11:05:00), "device-guid-2", "Finance-WKST2", "ProcessCreated", "svchost.exe", @"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs", "SYSTEM", "services.exe", "services.exe"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where FolderPath has "Photoes" and FolderPath has "Pics" // Fast token-based matching for the anomalous folder
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
