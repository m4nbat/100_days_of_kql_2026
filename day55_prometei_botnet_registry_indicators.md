# Name
Prometei Botnet - Registry Indicators

# Description
This detection identifies host-based indicators associated with the Prometei Botnet. Prometei is a modular botnet that utilizes a variety of techniques including "living-off-the-land" binaries (LOLBins), proprietary cryptomining modules, and credential theft tools.

The detection focuses on:
- Registry Persistence: Prometei stores configuration data (CommId, MachineKeyId) in a specific registry key.

Prometei stores configuration data (CommId, MachineKeyId, EncryptedMachineKeyId) in the registry key HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Intel\Support. This query monitors for modifications to these specific registry values.

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
- T1112: Modify Registry

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceRegistryEvents

# Query

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has "SOFTWARE\\WOW6432Node\\Intel\\Support"
| where RegistryValueName has_any ("CommId", "MachineKeyId", "EncryptedMachineKeyId")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, ProcessCommandLine
```
