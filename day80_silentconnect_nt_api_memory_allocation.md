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
   - DeviceEvents

# Query
## Query 3 - SILENTCONNECT Direct NT API Memory Allocation
This detection leverages DeviceEvents to identify direct NtAllocateVirtualMemoryApiCall actions. SILENTCONNECT uses this API call to allocate PAGE_EXECUTE_READWRITE memory for its shellcode, specifically attempting to bypass standard AV/EDR user-mode hooks on VirtualAlloc.

```kql
// let DeviceEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string,
//     InitiatingProcessAccountName: string
// )
// [
//     // Case 1: SILENTCONNECT allocating executable memory via NT API
//     datetime(2026-03-27 12:00:00), "Workstation01", "NtAllocateVirtualMemoryApiCall", "powershell.exe", "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Temp\\loader.ps1", "SYSTEM",
//     // Case 2: SILENTCONNECT masqueraded binary allocating memory
//     datetime(2026-03-27 12:05:00), "Workstation02", "NtAllocateVirtualMemoryApiCall", "winhlp32.exe", "winhlp32.exe", "SYSTEM",
//     // Case 3: Legitimate system process memory allocation
//     datetime(2026-03-27 12:10:00), "Workstation03", "NtAllocateVirtualMemoryApiCall", "csrss.exe", "csrss.exe", "SYSTEM"
// ];
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType == "NtAllocateVirtualMemoryApiCall"
// Filter out highly prevalent legitimate binaries making NT API memory calls to reduce noise
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "winhlp32.exe") 
    or InitiatingProcessFolderPath has @"\Temp\"
    or InitiatingProcessFolderPath has @"\Downloads\"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
