# Name
Bitdefender BDReinit.exe DLL Sideloading (log.dll)

# Description
Detects potential DLL sideloading or hijacking of log.dll by the legitimate BDReinit.exe (Bitdefender Antivirus Free) executable. Attackers can copy the legitimate BDReinit.exe to a user-writable directory (like \Downloads\ or \AppData\) and place a malicious log.dll in the same folder. When the executable runs, it loads the malicious DLL due to the Windows search order. This detection looks for log.dll being loaded from locations other than the expected Program Files directory.

# References
- https://hijacklibs.net/entries/3rd_party/bitdefender/log.html
- https://www.secureworks.com/research/shadowpad-malware-analysis

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- ShadowPad
- DLL Sideloading

MITRE ATT&CK
- T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking
- T1574.002 - Hijack Execution Flow: DLL Side-Loading

# Data Sources
- Microsoft Defender XDR
   - DeviceImageLoadEvents
   - DeviceProcessEvents
   - DeviceFileEvents

# Queries

## Query 1: Unexpected log.dll Image Load
This query identifies cases where BDReinit.exe loads log.dll from a directory that is not the standard Bitdefender installation path.

```
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FileName =~ "log.dll"
| where InitiatingProcessFileName =~ "BDReinit.exe"
// Filter out the legitimate installation path
| where not(FolderPath has_any(@"C:\Program Files\Bitdefender Antivirus Free\", @"C:\Program Files (x86)\Bitdefender Antivirus Free\"))
| project Timestamp, DeviceName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

## Query 2: BDReinit.exe Execution from Non-Standard Paths
Monitoring for the executable itself being moved to user-writable folders, which is a prerequisite for sideloading the DLL.

```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "BDReinit.exe"
// Focus on execution from suspicious or user-writable paths
| where FolderPath has_any(@"\Users\", @"\Downloads\", @"\Desktop\", @"\AppData\", @"\Temp\")
| project Timestamp, DeviceName, FolderPath, FileName, ProcessCommandLine, InitiatingProcessParentFileName, AccountName
```

# Query 3: Malicious File Creation Correlation
Identifies the creation of log.dll and BDReinit.exe in the same non-standard folder within a short timeframe.

```
let timeframe = 1h;
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("log.dll", "BDReinit.exe")
| where not(FolderPath has "Bitdefender")
| summarize 
    FilesCreated = make_set(FileName), 
    FirstSeen = min(Timestamp), 
    LastSeen = max(Timestamp) 
    by DeviceId, DeviceName, FolderPath, RequestAccountName
| where FilesCreated has "log.dll" and FilesCreated has "BDReinit.exe"
| project FirstSeen, LastSeen, DeviceName, FolderPath, FilesCreated, RequestAccountName
-
