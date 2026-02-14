# Name
Fake 7-Zip Proxyware - Network Communication to C2 (upStage Proxy)

# Description
In February 2026, a sophisticated malware campaign was identified abusing the popularity of the 7-Zip archiver. Threat actors used a lookalike domain (7zip[.]com) to distribute a trojanized installer. This query hunts for outbound connections to the specific "smshero" or "hero-sms" infrastructure used by the upStage Proxy malware to control residential proxy nodes.

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
- T1090.003: Proxy: Multi-hop Proxy
- T1082: System Information Discovery

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceNetworkEvents

# Query

```kql
// Detects network connections to identified C2 domains or proxy control endpoints
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("hero-sms", "herosms", "smshero") 
    or RemoteUrl in~ ("iplogger.org", "svc.ha-teams.office.com")
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
```