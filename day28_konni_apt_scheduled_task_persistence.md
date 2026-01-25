# Name
Konni APT - Scheduled Task Persistence

# Description
This detection identifies the creation of a scheduled task using the DeviceEvents table. In Microsoft Defender for Endpoint, the ScheduledTaskCreated ActionType provides high-fidelity telemetry for task registration. This specific query looks for the masqueraded "OneDrive Startup Task" used by the Konni APT, which executes a complex, obfuscated PowerShell command to decrypt a payload using XOR (Key 'Q').
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
- T1036.004 - Masquerading: Masquerade Task or Service

# Data Sources (Microsoft XDR)
- Microsoft Defender for Endpoint
  - DeviceFileEvents
  - DeviceProcessEvents

# Query
## Query 1: Detection of Malicious Scheduled Task Creation

```
// Detects the registration of the Konni-specific scheduled task
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| where AdditionalFields contains "OneDrive Startup Task"
// Additional check for the XOR-decryption logic within the task details if available
| where AdditionalFields contains "-bxor" and AdditionalFields contains "ReadAllBytes"

```

## Query 2: Broad Detection for Suspicious OneDrive Tasks

```
// Broader detection for any scheduled task masquerading as OneDrive outside of expected paths
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| where AdditionalFields contains "OneDrive"
// Filter for tasks pointing to ProgramData or containing PowerShell one-liners
| where AdditionalFields has_any (@"ProgramData","powershell", "-w","iex","invoke-expression")
// Exclude known legitimate OneDrive task names if they cause noise
| where FileName !~ "Name of Your Legit OneDrive Task" 

```
