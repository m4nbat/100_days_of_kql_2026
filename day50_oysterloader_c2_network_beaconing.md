# Name
OysterLoader - C2 Network Beaconing (Broomstick)

# Description
Detects indicators associated with OysterLoader (aka Broomstick/CleanUpLoader). This malware typically arrives via SEO poisoning impersonating legitimate software (e.g., PuTTY, Teams). This query identifies network connections to paths associated with OysterLoader's C2 infrastructure, specifically looking for API endpoints like /api/v2/init, /api/v2/facade, and other known C2 communication paths.

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
- Rhysida Ransomware (Affiliate Loader)

# MITRE ATT&CK
- T1071.001: Application Layer Protocol: Web Protocols
- T1095: Non-Application Layer Protocol

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceNetworkEvents

# Query

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("/api/v2/init", "/api/v2/facade", "/api/v2/YgePIY5zPSoGUjzRx7C50MTx6EzABXIPd")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
```