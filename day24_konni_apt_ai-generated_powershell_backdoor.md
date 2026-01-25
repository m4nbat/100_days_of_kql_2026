# Name
Konni APT - AI-Generated PowerShell Backdoor Staging

# Description
This query detects the initial staging behavior of the Konni APT's 2026 campaign. The infection chain involves a batch script creating a specific staging directory in C:\ProgramData and moving malicious PowerShell/Batch files there. It also looks for the execution of the first-stage batch file extracted from a CAB archive.

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
- T1059.001 - Command and Scripting Interpreter: PowerShell
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell
- T1564.001 - Hide Artifacts: Hidden Files and Directories

# Data Sources (Microsoft XDR)
- Microsoft Defender for Endpoint
  - DeviceFileEvents
  - DeviceProcessEvents

# Query
## Query 1: Malicious Staging in ProgramData
```
// Detects the creation of files in the ProgramData directory associated with Konni staging
DeviceFileEvents
| where FolderPath startswith @"C:\ProgramData\"
| where FileName endswith ".ps1" or FileName endswith ".bat"
| where InitiatingProcessFileName =~ "cmd.exe" or InitiatingProcessFileName =~ "powershell.exe"

```

## Query 2: Execution of PowerShell Backdoor from ProgramData
```
// Detects the execution of PowerShell scripts from the ProgramData staging area
DeviceProcessEvents
| where ProcessCommandLine has @"C:\ProgramData\"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (".ps1", "IEX", "Invoke-Expression")

```


