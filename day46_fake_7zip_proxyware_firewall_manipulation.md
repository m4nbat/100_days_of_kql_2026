# Name
Fake 7-Zip Proxyware - Firewall Rule Manipulation (upStage Proxy)

# Description
In February 2026, a sophisticated malware campaign was identified abusing the popularity of the 7-Zip archiver. Threat actors used a lookalike domain (7zip[.]com) to distribute a trojanized installer. This query detects the use of netsh to create allow rules for the malicious binaries, which is a key TTP for this campaign to enable outbound proxy traffic.

# References
- https://www.malwarebytes.com/blog/threat-intel/2026/02/fake-7-zip-downloads-are-turning-home-pcs-into-proxy-nodes

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- upStage Proxy

# MITRE ATT&CK
- T1562.004: Impair Defenses: Disable or Modify System Firewall
- T1090.003: Proxy: Multi-hop Proxy

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
// Detects netsh commands adding firewall exceptions for the proxyware binaries
DeviceProcessEvents
| where FileName =~ "netsh.exe" and ProcessCommandLine has_all ( "advfirewall firewall","add","rule","allow" ) and ProcessCommandLine has_any ("hero.exe", "Uphero.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ParentProcessFileName
```