# Name
Prometei Botnet - Persistence and Defense Evasion

# Description
This detection identifies host-based indicators associated with the Prometei Botnet. Prometei is a modular botnet that utilizes a variety of techniques including "living-off-the-land" binaries (LOLBins), proprietary cryptomining modules, and credential theft tools.

The detection focuses on:
- Persistence: Creation of the UPlugPlay service.
- Defense Evasion: Specific netsh firewall rule additions and Add-MpPreference exclusions used by the botnet.

This query detects the specific command lines used to create the malicious service UPlugPlay, modify firewall rules for sqhost.exe, and add Defender exclusions for the staging path.

# References
- https://www.esentire.com/blog/tenant-from-hell-prometeis-unauthorized-stay-in-your-windows-server

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Prometei Botnet

# MITRE ATT&CK
- T1543.003: Create or Modify System Process: Windows Service
- T1562.004: Impair Defenses: Disable or Modify System Firewalls
- T1562.001: Impair Defenses: Disable or Modify Tools

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents

# Query

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("UPlugPlay", "sqhost.exe", "C:\\Windows\\Dell")
| where (ProcessCommandLine has "netsh" and ProcessCommandLine has "firewall" and ProcessCommandLine has "add" and ProcessCommandLine has "sqhost.exe")
     or (ProcessCommandLine has "sc" and ProcessCommandLine has "create" and ProcessCommandLine has "UPlugPlay")
     or (ProcessCommandLine has "Add-MpPreference" and ProcessCommandLine has "ExclusionPath" and ProcessCommandLine has "Dell")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```
