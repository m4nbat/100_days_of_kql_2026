# Name
BRUSHWORM and BRUSHLOGGER Activity - Removable Media Worm Propagation Lures

# Description
This detection identifies indicators of compromise (IOCs) associated with the BRUSHWORM and BRUSHLOGGER malware, newly identified custom malware components observed targeting financial institutions. BRUSHWORM acts as a modular backdoor and worm that propagates via USB removable media using socially engineered filenames (e.g., Salary Slips.exe). It installs itself into a misspelled directory C:\ProgramData\Photoes\Pics\ and stores an encrypted configuration file in a non-standard public profile path C:\Users\Public\AppData\Roaming\Microsoft\Vault\keyE.dat. BRUSHLOGGER is a complementary DLL-side-loaded keylogger used for stealing credentials and keystrokes.

This query searches for the creation of executable files using social engineering lures identical to those observed in BRUSHWORM's removable media propagation routine.

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
  - DeviceFileEvents

# Query
## Query 3: BRUSHWORM Removable Media Worm Propagation Lures

```kql
// let DeviceFileEvents = datatable(
//     Timestamp: datetime,
//     DeviceId: string,
//     DeviceName: string,
//     ActionType: string,
//     FileName: string,
//     FolderPath: string,
//     SHA256: string,
//     InitiatingProcessAccountName: string,
//     InitiatingProcessFileName: string
// )
// [
//     // Case 1: BRUSHWORM propagation file drop
//     datetime(2026-03-27 12:00:00), "device-guid-1", "Finance-WKST1", "FileCreated", "Salary Slips.exe", @"E:\Salary Slips.exe", "e3b0c442...", "SYSTEM", "brushworm.exe",
//     // Case 2: BRUSHWORM propagation file drop 2
//     datetime(2026-03-27 12:05:00), "device-guid-2", "Finance-WKST2", "FileCreated", "Dont Delete.exe", @"F:\Dont Delete.exe", "a5b3c2d1...", "SYSTEM", "brushworm.exe",
//     // Case 3: Legitimate file (should not trigger)
//     datetime(2026-03-27 12:10:00), "device-guid-3", "Finance-WKST3", "FileCreated", "Salary Slips.xlsx", @"E:\Salary Slips.xlsx", "b2c3d4e5...", "jdoe", "excel.exe"
// ];
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in~ ("FileCreated", "FileRenamed")
| where FileName in~ (
    "Salary Slips.exe",
    "Notes.exe",
    "Documents.exe",
    "Important.exe",
    "Dont Delete.exe",
    "Presentation.exe",
    "Emails.exe",
    "Attachments.exe"
)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, SHA256
```
