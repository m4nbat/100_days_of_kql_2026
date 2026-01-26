# Name
Konni APT - PowerShell Backdoor Anti-Analysis & Fingerprinting

# Description
The AI-generated Konni backdoor includes user-interaction checks (monitoring mouse clicks) and fingerprints the system by querying WMI for the motherboard serial number and system UUID to generate a unique host identifier.

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
- T1497.001 - Virtualization/Sandbox Evasion: System Checks
- T1082 - System Information Discovery

# Data Sources (Microsoft XDR)
- Microsoft Defender for Endpoint
  - DeviceEvents
  - DeviceProcessEvents

# Query
## Query 1: WMI Fingerprinting via PowerShell
```
// Detects PowerShell commands querying hardware identifiers commonly used for fingerprinting
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "Win32_BaseBoard" or ProcessCommandLine has "Win32_ComputerSystemProduct"
| where ProcessCommandLine has_any ("SerialNumber", "UUID")

```

## Query 2: Obfuscated PowerShell (XOR Decoding)
```
// Detects the specific XOR decryption pattern (Key 'Q') mentioned in the report
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-bxor" and ProcessCommandLine has "81" // 81 is the decimal for 'Q' if used in certain logic, or look for 'Q'
| where ProcessCommandLine has "IEX" or ProcessCommandLine has "Invoke-Expression"

```
