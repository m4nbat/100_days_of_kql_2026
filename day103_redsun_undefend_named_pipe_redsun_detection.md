# Name
UnDefend and RedSun (Microsoft Defender Zero-Days) Exploitation Activity: REDSUN Named Pipe Detection

# Description
This detection identifies the creation of the hardcoded named pipe `\pipe\REDSUN` used by the RedSun zero-day payload to deliver an interactive SYSTEM shell to the attacker. The named pipe is a unique and high-fidelity indicator of compromise associated with this exploitation chain, where Defender is weaponised to write an attacker-controlled binary to TieringEngineService.exe.

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
- T1559 - Inter-Process Communication

# Data Sources
- Microsoft 365 Defender
  - DeviceEvents

# Query
## Query 2: REDSUN Named Pipe Creation Detection
Detects the hardcoded named pipe `\pipe\REDSUN` utilised by the RedSun payload for delivering the interactive shell.

```kql
// Testing datatable for logic validation
let DeviceEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    ActionType: string,
    InitiatingProcessFileName: string,
    AdditionalFields: string
)
[
    // Case 1: RedSun payload named pipe creation
    datetime(2026-04-17 08:05:00), "device-guid-1", "Victim-PC", "NamedPipeEvent", 
    "TieringEngineService.exe", 
    "{\"PipeName\":\"\\\\\\\\.\\\\pipe\\\\REDSUN\",\"Operation\":\"Created\"}"
];
// Detection Logic
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where AdditionalFields has "REDSUN"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, AdditionalFields
```
