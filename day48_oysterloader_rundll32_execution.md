# Name
OysterLoader - Suspicious Rundll32 Execution (Broomstick)

# Description
Detects indicators associated with OysterLoader (aka Broomstick/CleanUpLoader). This malware typically arrives via SEO poisoning impersonating legitimate software (e.g., PuTTY, Teams). This query looks for rundll32.exe executing a DLL with the specific export function Test, which is a high-fidelity indicator for OysterLoader's dropped payload, particularly when running from suspicious directories like Temp or ProgramData.

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
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
// The malware specifically uses the export "Test" and often runs from Temp/ProgramData
| where ProcessCommandLine has "Test" 
| where ProcessCommandLine has_any ("temp", "programdata", "appdata", "public")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
```