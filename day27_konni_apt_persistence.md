# Name
Konni APT - Scheduled Task Persistence & Malicious Batch Staging

# Description
This detection focuses on the specific persistence mechanism used by Konni APT as described in the Check Point report. It targets the execution of a batch script that creates a hidden staging directory in C:\ProgramData, moves malicious components (PowerShell and Batch files), and registers a scheduled task masquerading as a "OneDrive Startup Task". The scheduled task contains an inline PowerShell command that performs XOR decryption (Key 'Q') of a staged file before executing it in memory.

# References
https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Konni
- APT37

# MITRE ATT&CK
- T1053.005 - Scheduled Task/Job: Scheduled Task
- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1140 - Deobfuscate/Decode Files or Information
- T1036.004 - Masquerading: Masquerade Task or Service

# Data Sources (Microsoft XDR)
- Microsoft Defender for Endpoint
  - DeviceFileEvents
  - DeviceProcessEvents

# Query
## Query 1: Detection of Malicious Scheduled Task Creation
This query monitors for the ```schtasks.exe``` command line provided in the snippet, looking for the masqueraded task name and the specific XOR-based PowerShell execution string.
```
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_all ("OneDrive","Startup","Task")
| where ProcessCommandLine has_all ("-bxor", "ReadAllBytes", "iex")
// Highlighting the specific XOR key logic 'Q' mentioned in the attack
| where ProcessCommandLine has_all ( @"[Text.Encoding]::UTF8.GetBytes","Q",@"(",@")" )

```

## Query 2: Batch File Staging and Component Movement
This query detects the behavior of a batch file moving ```.ps1``` or ```.bat``` files into newly created subdirectories within ```C:\ProgramData```, which is a deviation from standard OneDrive or system behavior.
```
DeviceFileEvents
| where ActionType =~ "FileCreated"
| where FolderPath startswith @"C:\ProgramData\"
| where FileName endswith ".ps1" or FileName endswith ".bat"
| where InitiatingProcessFileName =~ "cmd.exe"
// Filter for movement into non-standard ProgramData subfolders
| where FolderPath !has "Microsoft" and FolderPath !has "Package Cache"

```

## Query 3: Execution of Masqueraded OneDrive Updater
The script ends by executing a file named OneDriveUpdater.exe from C:\ProgramData. Legitimate OneDrive binaries typically run from LocalAppdata or Program Files.
```
DeviceProcessEvents
| where FileName =~ "OneDriveUpdater.exe"
| where FolderPath has @"C:\ProgramData"
```

