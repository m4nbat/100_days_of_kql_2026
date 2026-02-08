# Name
UAC Disabled via Registry Modification (KONNI)

# Description
Detects modifications to the User Account Control (UAC) registry key ConsentPromptBehaviorAdmin where the value is set to 0. This specific configuration allows administrative actions to proceed without prompting the user for consent, effectively bypassing UAC. This technique (T1112) was recently observed being used by the KONNI threat group to maintain elevated access without alerting the victim.

# References
- https://www.knowyouradversary.ru/2026/01/370-adversaries-disable-uac-prompts-for.html

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- KONNI

# MITRE ATT&CK
- T1112 (Modify Registry)
- T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)
- T1059 (Command and Scripting Interpreter)

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceRegistryEvents
  - DeviceProcessEvents
- Microsoft Sentinel
  - SecurityEvent

# Query

## Query 1: Registry Key Modification (DeviceRegistryEvents)
Detects the specific registry value set operation on endpoints.

```kql
DeviceRegistryEvents
// Filter for the specific UAC policy registry key
| where RegistryKey has "ConsentPromptBehaviorAdmin"
// Detect setting the value to '0' (Silent elevation)
| where RegistryValueData == "0" or RegistryValueData == "0x00000000"
```

## Query 2: Registry Modification via Command Line (DeviceProcessEvents)
Detects command-line attempts (reg.exe, powershell.exe) to modify this specific key, which may occur before the registry event is logged.

```kql
DeviceProcessEvents
| where FileName in~ ("reg.exe", "powershell.exe", "cmd.exe")
// Look for the target key and the malicious value '0' in the arguments
| where ProcessCommandLine has "ConsentPromptBehaviorAdmin"
| where ProcessCommandLine has "0" 
// Ensure it is a write/add operation (for reg.exe)
| where ProcessCommandLine has_any ("add", "set-itemproperty", "new-itemproperty")
```
