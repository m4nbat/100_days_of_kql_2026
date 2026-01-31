# Name
APT36 - Obfuscated Command Line (Caret Insertion)

# Description
Detects cmd.exe or powershell.exe execution where the command line contains excessive "caret" (^) symbols. APT36 uses this technique (e.g., c^m^d^.^e^x^e) to bypass simple keyword-based detection engines while remaining executable by the Windows command processor.

# References
https://www.cyfirma.com/research/apt36-lnk-based-malware-campaign-leveraging-msi-payload-delivery/

# Author
- M4nbat

# Threats
- APT36
- Transparent Tribe

# MITRE ATT&CK
- T1027 - Obfuscated Files or Information
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell

# Data Sources
- Microsoft XDR
   - DeviceProcessEvents

# Queries

## Query 1: Caret Obfuscation Detection
Uses regex to find instances where characters are frequently separated by carets.

```
// Mock data for testing
// let DeviceProcessEvents = datatable(Timestamp:datetime, DeviceName:string, FileName:string, ProcessCommandLine:string)
// ["2025-12-30", "GOV-PC-01", "cmd.exe", "c^m^d^.^e^x^e /c ^m^s^h^t^a^..."];
DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
// Look for at least 5 carets in the command line (adjust threshold based on false positives)
| where countof(ProcessCommandLine, "^") > 5
// Specifically look for the pattern of Character^Character
| where ProcessCommandLine matches regex @"([a-zA-Z0-9]\^){3,}"
```
