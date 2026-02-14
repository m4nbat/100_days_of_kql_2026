# Name
Fake 7-Zip Proxyware - Service Installation (upStage Proxy)

# Description
In February 2026, a sophisticated malware campaign was identified abusing the popularity of the 7-Zip archiver. Threat actors used a lookalike domain (7zip[.]com) to distribute a trojanized installer. This query detects the registration of the malicious "Uphero" or "hero" Windows services via registry modification, which is a key persistence mechanism used by the upStage Proxy malware.

# References
- https://www.malwarebytes.com/blog/threat-intel/2026/02/fake-7-zip-downloads-are-turning-home-pcs-into-proxy-nodes

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- upStage Proxy
- Uphero
- hero.exe

# MITRE ATT&CK
- T1543.003: Create or Modify System Process: Windows Service
- T1012: Query Registry

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceRegistryEvents

# Query

```kql
// Detects the creation of the Windows Service for persistence
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"SYSTEM\CurrentControlSet\Services"
| where (RegistryKey has "Uphero" or RegistryKey has "hero")
| where ActionType == "RegistryKeyCreated"
| project Timestamp, DeviceName, ActionType, RegistryKey, InitiatingProcessCommandLine
```