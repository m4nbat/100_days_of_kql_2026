# Name
Creation of .proj file in suspicious location eventually used to to bypass AV detection with msbuild.exe use.

# Description
Creation of .proj file in suspicious location eventually used to to bypass AV detection with msbuild.exe use.

<img width="1600" height="951" alt="image" src="https://github.com/user-attachments/assets/adea3f15-2dee-4a99-922b-207a973c1c2b" />

# References
- https://www.bleepingcomputer.com/news/security/clickfix-attack-uses-fake-windows-bsod-screens-to-push-malware/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- ASyncRAT
- ClickFix

# MITRE ATT&CK
- Defense Evasion
- T1562 : Impair Defenses
- T1562.001 Impair Defenses: Disable or Modify Tools
- T1127.001 Trusted Developer Utilities Proxy Execution: MSBuild

# Data Sources
- MDE
  - DeviceFileEvents

# Query

```
// source: https://www.bleepingcomputer.com/news/security/clickfix-attack-uses-fake-windows-bsod-screens-to-push-malware/
// Creation of a suspicious .proj file in suspicious location eventually used to to bypass AV detection with msbuild.exe use.
DeviceFileEvents
| where ActionType =~ "FileCreated" and FolderPath has @":\ProgramData" and FileName matches regex @"^.\.proj$

```
