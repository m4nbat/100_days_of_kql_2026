# Name
OysterLoader - Scheduled Task Persistence (Broomstick)

# Description
Detects indicators associated with OysterLoader (aka Broomstick/CleanUpLoader). This malware typically arrives via SEO poisoning impersonating legitimate software (e.g., PuTTY, Teams). This query detects the creation of the specific scheduled task "ClearMngs" used by OysterLoader for persistence, which typically executes rundll32.exe with the Test export function.

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
- T1053.005: Scheduled Task/Job: Scheduled Task
- T1218.011: System Binary Proxy Execution: Rundll32

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "create" and ( ProcessCommandLine has "ClearMngs" or ( ProcessCommandLine has "rundll32" and ProcessCommandLine has "Test") )
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```