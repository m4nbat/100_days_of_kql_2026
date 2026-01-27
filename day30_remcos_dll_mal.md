# Name
Remcos RAT via DLL Side-Loading (Quick Share)

# Description
Detects potential Remcos RAT execution leveraging DLL side-loading through the legitimate ```nearby_share.exe``` (Quick Share) binary. Red Canary observed Scarlet Goldfinch deploying Remcos in December 2025/January 2026 using this specific technique to evade detection by piggybacking on a trusted Google/Samsung binary.

# References
- https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Scarlet Goldfinch
- RemcosRAT
- Remcos

# MITRE ATT&CK
- T1574.002 - Hijack Execution Flow: DLL Side-Loading

# Data Sources
- Microsoft Defender for Endpoint
    - DeviceProcessEvents
    - DeviceImageLoadEvents

# Query

## Query 1: Remcos Side-loading via Quick Share (Process Correlation)
```
// Detects the legitimate Quick Share binary being used in an unusual context 
// or spawning suspicious child processes often associated with Remcos
DeviceProcessEvents
| where InitiatingProcessFileName =~ "nearby_share.exe"
// Look for nearby_share spawning cmd, powershell, or other suspicious tools
| where FileName in~ ("cmd.exe", "powershell.exe", "schtasks.exe", "werfault.exe")
```

## Query 2: Remcos DLL Loading (Image Load)
```
// Remcos often uses a malicious DLL (e.g., libcef.dll or others) placed in the same folder as a legitimate EXE
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "nearby_share.exe"
// Filter for DLLs loaded from unusual paths or known Remcos side-loading targets
| where Initiating ProcessFolderPath has_any ("AppData", "Temp", "Public")
```
