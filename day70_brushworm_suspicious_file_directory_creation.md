# Name
BRUSHWORM and BRUSHLOGGER Activity - Suspicious File and Directory Creation

# Description
This detection identifies indicators of compromise (IOCs) associated with the BRUSHWORM and BRUSHLOGGER malware, newly identified custom malware components observed targeting financial institutions. BRUSHWORM acts as a modular backdoor and worm that propagates via USB removable media using socially engineered filenames (e.g., Salary Slips.exe). It installs itself into a misspelled directory C:\ProgramData\Photoes\Pics\ and stores an encrypted configuration file in a non-standard public profile path C:\Users\Public\AppData\Roaming\Microsoft\Vault\keyE.dat. BRUSHLOGGER is a complementary DLL-side-loaded keylogger used for stealing credentials and keystrokes.

This query detects the creation of the misspelled "Photoes" directory, the anomalous keyE.dat configuration file, and the Recorder.dll module in the Public\Libraries folder.

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
## Query 1: BRUSHWORM Suspicious File and Directory Creation

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
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string
// )
// [
//     // Case 1: BRUSHWORM main installation folder creation
//     datetime(2026-03-27 10:00:00), "device-guid-1", "Finance-WKST1", "FileCreated", "brushworm.exe", @"C:\ProgramData\Photoes\Pics\brushworm.exe", "e3b0c442...", "SYSTEM", "cmd.exe", "cmd.exe /c start brushworm.exe",
//     // Case 2: BRUSHWORM config file creation in public appdata
//     datetime(2026-03-27 10:05:00), "device-guid-2", "Finance-WKST2", "FileCreated", "keyE.dat", @"C:\Users\Public\AppData\Roaming\Microsoft\Vault\keyE.dat", "a5b3c2d1...", "SYSTEM", "brushworm.exe", "brushworm.exe",
//     // Case 3: BRUSHLOGGER DLL drop
//     datetime(2026-03-27 10:10:00), "device-guid-3", "Finance-WKST3", "FileCreated", "Recorder.dll", @"C:\Users\Public\Libraries\Recorder.dll", "b2c3d4e5...", "SYSTEM", "brushworm.exe", "brushworm.exe",
//     // Case 4: Normal baseline activity (should not trigger)
//     datetime(2026-03-27 10:15:00), "device-guid-4", "Finance-WKST4", "FileCreated", "legit.txt", @"C:\Users\Public\Documents\legit.txt", "12345678...", "jdoe", "explorer.exe", "explorer.exe"
// ];
DeviceFileEvents
| where Timestamp > ago(14d) // Filter early for performance
| where ActionType in~ ("FileCreated", "FileRenamed", "FileModified")
| where (FolderPath has "Photoes" and FolderPath has "Pics") // Catches C:\ProgramData\Photoes\Pics\
   or (FolderPath has "keyE.dat" and FolderPath has "Vault") // Catches C:\Users\Public\AppData\Roaming\Microsoft\Vault\keyE.dat
   or (FolderPath has "Libraries" and FileName =~ "Recorder.dll") // Catches C:\Users\Public\Libraries\Recorder.dll
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```
