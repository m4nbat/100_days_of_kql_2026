# Name
Konni APT - Fodhelper UAC Bypass

# Description
The Konni AI-generated backdoor checks privilege levels. If running as a standard user, it employs the ```fodhelper.exe``` UAC bypass technique. This is achieved by modifying registry keys under ```HKCU\Software\Classes``` to redirect the ```ms-settings``` protocol.

# References
https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Konni
- APT37

# MITRE ATT&CK
- T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control

# Data Sources (Microsoft XDR)
- Microsoft Defender for Endpoint
  - DeviceRegistryEvents
  - DeviceProcessEvents

# Query
## Query 1: Fodhelper Registry Hijack
```
// Detects registry modifications to the ms-settings protocol for UAC bypass
DeviceRegistryEvents
| where RegistryKey has @"Software\Classes\ms-settings\Shell\Open\command"
| where RegistryValueName =~ "(Default)" or RegistryValueName == ""

```

## Query 2: Fodhelper Spawned by PowerShell/Batch
```
// Detects the execution of fodhelper.exe when initiated by a script or suspected loader
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "fodhelper.exe"
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "wscript.exe")

```
