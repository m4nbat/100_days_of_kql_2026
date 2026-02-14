# Name
Fake 7-Zip Proxyware Campaign - File Creation Detection

# Description
In February 2026, a sophisticated malware campaign was identified abusing the popularity of the 7-Zip archiver. Threat actors used a lookalike domain (7zip[.]com) to distribute a trojanized installer. While providing a functional version of 7-Zip, the installer silently drops three components into C:\Windows\SysWOW64\hero\. These components convert the victim's machine into a residential proxy node, allowing third parties to route potentially malicious traffic through the victim's IP address. This query detects the deployment of the proxyware components in the SysWOW64 directory.

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
- T1036.007: Masquerading: Double File Extension (Lookalike domains)
- T1543.003: Create or Modify System Process: Windows Service

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceFileEvents

# Query

``` 
// Detects the deployment of the proxyware components in the SysWOW64 directory
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"C:\Windows\SysWOW64\hero"
| where FileName in~ ("Uphero.exe", "hero.exe", "hero.dll")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
```