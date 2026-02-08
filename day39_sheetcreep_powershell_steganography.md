# Name
PowerShell Loading Malicious Payload from Image (SHEETCREEP)

# Description
Detects PowerShell commands attempting to read binary data from image files (specifically .png) and load them as .NET assemblies using System.Reflection. This behavior is indicative of the SHEETCREEP backdoor loader mechanism, where an LNK file triggers PowerShell to read, reverse, and execute malicious byte arrays hidden in image files.

# References
- https://www.knowyouradversary.ru/2026/01/371-adversaries-disguise-malicious.html

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- SHEETCREEP

# MITRE ATT&CK
- T1059.001 (Command and Scripting Interpreter: PowerShell)
- T1027 (Obfuscated Files or Information)
- T1027.003 (Obfuscated Files or Information: Steganography)

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents
- Microsoft Sentinel
  - SecurityEvent
  - Sysmon (Event ID 1)

# Query

## Query 1: PowerShell Loading Assembly from Image (High Fidelity)
Detects the specific combination of reading bytes from an image file and immediately loading them as a .NET assembly via Reflection, a technique used by SHEETCREEP.

```kql
// Microsoft Defender for Endpoint (DeviceProcessEvents)
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
// Look for the specific .NET methods used to read the payload and load the assembly
| where ProcessCommandLine has_all ("ReadAllBytes", "System.Reflection.Assembly", "Load")
// Filter for common image extensions used in this technique
| where ProcessCommandLine has_any (".png", ".jpg", ".jpeg", ".bmp", ".gif")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

## Query 2: PowerShell Byte Array Reversal (Specific Campaign TTP)
Detects the specific byte reversal logic ($b.Length-1)..0 observed in the SHEETCREEP loader command line, which is used to reconstruct the payload before execution.

```kql
// Microsoft Defender for Endpoint (DeviceProcessEvents)
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
// The distinct byte reversal array slicing syntax used by the malware
| where ProcessCommandLine has "Length-1" and ProcessCommandLine has "..0"
| where ProcessCommandLine has "IO.File"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```
