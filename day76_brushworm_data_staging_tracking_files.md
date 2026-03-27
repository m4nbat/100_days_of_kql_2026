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
   - DeviceFileEvents

# Query
## Query 2 - BRUSHWORM Data Staging and Tracking Files
This query identifies the unique data staging behaviors of BRUSHWORM, which moves targeted files (documents, spreadsheets, source code) to the C:\Users\Public\Systeminfo\ directory and tracks successfully exfiltrated files using a file named hashconfig in the NuGet roaming profile directory.

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
//     // Case 1: BRUSHWORM hash tracking file creation
//     datetime(2026-03-27 11:00:00), "device-guid-1", "Finance-WKST1", "FileCreated", "hashconfig", @"C:\Users\Public\AppData\Roaming\NuGet\hashconfig", "e3b0c442...", "SYSTEM", "brushworm.exe", "brushworm.exe",
//     // Case 2: BRUSHWORM data staging directory usage
//     datetime(2026-03-27 11:05:00), "device-guid-2", "Finance-WKST2", "FileCreated", "stolen_data.zip", @"C:\Users\Public\Systeminfo\stolen_data.zip", "a5b3c2d1...", "SYSTEM", "brushworm.exe", "brushworm.exe",
//     // Case 3: Standard legitimate file creation (should not trigger)
//     datetime(2026-03-27 11:10:00), "device-guid-3", "Finance-WKST3", "FileCreated", "config.xml", @"C:\Users\Public\AppData\Roaming\NuGet\config.xml", "b2c3d4e5...", "jdoe", "devenv.exe", "devenv.exe"
// ];
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in~ ("FileCreated", "FileRenamed", "FileModified")
| where (FolderPath has "Systeminfo" and FolderPath has @"C:\Users\Public\")
   or (FileName =~ "hashconfig" and FolderPath has "NuGet")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```
