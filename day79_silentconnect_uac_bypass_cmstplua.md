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
## Query 2 - SILENTCONNECT UAC Bypass via CMSTPLUA COM Interface
This query identifies the UAC bypass technique leveraged by SILENTCONNECT. By exploiting the CMSTPLUA COM interface via LaunchElevatedCOMObjectUnsafe, the malware causes the COM Surrogate (dllhost.exe) to spawn the payload with high integrity/elevated privileges.

```kql
// let DeviceProcessEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     FileName: string,
//     ProcessCommandLine: string,
//     AccountName: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string,
//     ProcessTokenElevation: string
// )
// [
//     // Case 1: SILENTCONNECT UAC Bypass leading to elevated installer execution
//     datetime(2026-03-27 11:00:00), "Workstation01", "ProcessCreated", "msiexec.exe", "msiexec.exe /i C:\\Temp\\ScreenConnect.ClientSetup.msi /qn", "SYSTEM", "dllhost.exe", "dllhost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", "TokenElevationTypeFull",
//     // Case 2: SILENTCONNECT UAC Bypass spawning PowerShell
//     datetime(2026-03-27 11:05:00), "Workstation02", "ProcessCreated", "powershell.exe", "powershell.exe -c \"Start-Process msiexec.exe...\"", "admin", "dllhost.exe", "dllhost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", "TokenElevationTypeFull",
//     // Case 3: Legitimate dllhost execution (Thumbnail extraction, etc.)
//     datetime(2026-03-27 11:10:00), "Workstation03", "ProcessCreated", "dllhost.exe", "dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}", "jdoe", "svchost.exe", "svchost.exe -k DcomLaunch", "TokenElevationTypeDefault"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName =~ "dllhost.exe"
// The CMSTPLUA CLSID is commonly abused, capturing dllhost spawning scripts or installers is a strong signal
| where InitiatingProcessCommandLine has "3E5FC7F9-9A51-4367-9063-A120244FBEC7"
   or FileName in~ ("powershell.exe", "pwsh.exe", "msiexec.exe", "cmd.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessTokenElevation
```
