# Name
UnDefend and RedSun (Microsoft Defender Zero-Days) Exploitation Activity: TieringEngineService.exe Interactive Shell Execution

# Description
This detection identifies anomalous interactive shell execution originating from TieringEngineService.exe, which is a key indicator of the RedSun zero-day exploitation chain. RedSun abuses the Defender cloud file rollback mechanism: threat actors trigger a Defender scan using a crafted file, then utilise oplocks and NTFS junction points to hijack the remediation process, forcing Defender to write an attacker-controlled payload to C:\Windows\System32\TieringEngineService.exe. This payload runs as SYSTEM and often spawns an interactive shell (e.g. conhost.exe, cmd.exe, powershell.exe) via a named pipe \pipe\REDSUN.

# References
- https://www.cloudsek.com/blog/redsun-windows-0day-when-defender-becomes-the-attacker
- https://socradar.io/blog/bluehammer-redsun-undefend-windows-defender-0days/
- https://www.helpnetsecurity.com/2026/04/17/microsoft-defender-zero-days-exploited/
- https://x.com/i/status/2044882050314817880

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Chaotic Eclipse / Nightmare Eclipse (Exploit Authors)
- BlueHammer
- RedSun
- UnDefend

# MITRE ATT&CK
- T1068 - Exploitation for Privilege Escalation
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell

# Data Sources
- Microsoft 365 Defender
  - DeviceProcessEvents

# Query
## Query 1: RedSun Payload Execution - TieringEngineService.exe Spawning Interactive Shell
Detects anomalous interactive shell execution originating from TieringEngineService.exe (RedSun Payload Execution).

```kql
// Testing datatable for logic validation
let DeviceProcessEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    ActionType: string,
    FileName: string,
    FolderPath: string,
    SHA256: string,
    ProcessCommandLine: string,
    ProcessId: long,
    AccountName: string,
    AccountDomain: string,
    InitiatingProcessFileName: string,
    InitiatingProcessCommandLine: string,
    InitiatingProcessId: long,
    InitiatingProcessParentFileName: string
)
[
    // Case 1: RedSun exploitation spawning a SYSTEM shell
    datetime(2026-04-17 08:00:00), "device-guid-1", "Victim-PC", "ProcessCreated", 
    "conhost.exe", "C:\\Windows\\System32\\conhost.exe", "abcdef...", 
    "conhost.exe", 1337, "SYSTEM", "NT AUTHORITY", 
    "TieringEngineService.exe", "TieringEngineService.exe", 1336, "svchost.exe"
];
// Detection Logic
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName =~ "TieringEngineService.exe"
| where FileName in~ ("conhost.exe", "cmd.exe", "powershell.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
