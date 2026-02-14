# Name
OysterLoader - Suspicious Rundll32 Execution (Sentinel)

# Description
Detects indicators associated with OysterLoader (aka Broomstick/CleanUpLoader). This malware typically arrives via SEO poisoning impersonating legitimate software (e.g., PuTTY, Teams). This query provides equivalent detection for Microsoft Sentinel using Windows Event Logs (Event ID 4688), looking for rundll32.exe executing a DLL with the specific export function Test from suspicious directories.

# References
- https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
- https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win64/Oysterloader.AO!MTB

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- OysterLoader
- Broomstick
- CleanUpLoader
- Rhysida Ransomware

# MITRE ATT&CK
- T1218.011: System Binary Proxy Execution: Rundll32
- T1204.001: User Execution: Malicious Link
- T1027: Obfuscated Files or Information

# Data Sources
- Microsoft Sentinel
  - SecurityEvent (Windows)

# Query

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has "rundll32.exe"
| where CommandLine has "Test"
| where CommandLine has_any ("temp", "programdata", "appdata", "public")
| project TimeGenerated, Computer, SubjectUserName, CommandLine, ParentProcessName, NewProcessName
```