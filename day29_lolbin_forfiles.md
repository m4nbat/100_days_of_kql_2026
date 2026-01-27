# Name
Indirect Execution via forfiles.exe

# Description
Identifies the use of the native Windows utility ```forfiles.exe``` to execute commands indirectly. This technique is highlighted in the January 2026 Red Canary insights as a method used by adversaries to bypass command-line monitoring or execution restrictions by masking the actual payload execution within the ```/c``` parameter of forfiles.

# References
[https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- RemcosRAT
- Remcos

# MITRE ATT&CK
- T1202 - Indirect Command Execution

# Data Sources (Microsoft XDR)
- Microsoft Defender for Endpoint
    - DeviceProcessEvents
      
# Queries
## Query 1: Focus on forfiles executing commands via the /c parameter

```
// Focus on forfiles executing commands via the /c parameter
DeviceProcessEvents
// Filter for the specific utility
| where FileName =~ "forfiles.exe" or ProcessCommandLine has "forfiles"
// Look for the execution flag /c followed by a command
| where ProcessCommandLine has "/c"

```

## Query 2: Focus on forfiles executing commands seen by Red Canary MDR

```
// Focus on forfiles executing commands via the /c parameter
DeviceProcessEvents
// Filter for the specific utility
| where FileName =~ "forfiles.exe" or ProcessCommandLine has "forfiles"
// Look for the execution flags
| where ProcessCommandLine has_all ("/c","/p","/m") or ProcessCommandLine has_all ("-c","-p","-m")

```
