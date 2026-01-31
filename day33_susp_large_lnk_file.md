# Name
APT36 - Large LNK File Creation/Execution

# Description
Detects the execution of an unusually large Windows Shortcut (LNK) file that triggers mshta.exe. APT36 uses LNK files inflated to ~2MB (containing embedded PDF structures) to masquerade as legitimate documents. When clicked, these shortcuts execute a command line that calls mshta.exe to fetch a remote HTA payload.

# References
- https://www.cyfirma.com/research/apt36-multi-stage-lnk-malware-campaign-targeting-indian-government-entities/
- https://www.esecurityplanet.com/threats/apt36-uses-malicious-windows-shortcuts-to-target-indian-government/

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- APT36
- Transparent Tribe

# MITRE ATT&CK
- T1204.002 - User Execution: Malicious File
- T1204 - User Execution

# Data Sources
- Microsoft XDR
  - DeviceProcessEvents
  - DeviceFileEvents

# Query

Query 1: Large LNK File Creation/Execution
APT36 uses LNK files > 2MB to mimic PDF sizes. Standard LNKs are < 10KB.

```
// Monitor for creation of unusually large LNK files
DeviceFileEvents
| where ActionType =~ "FileCreated" and FileName endswith ".lnk"
// LNK files are typically ~1.5KB - 4KB. 1MB (1048576) is a very safe threshold for "Abnormal"
| where FileSize > 1000000 
| project Timestamp, DeviceName, FileName, FolderPath, FileSize, SHA256
```
