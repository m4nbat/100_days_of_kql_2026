# Name
BRUSHWORM and BRUSHLOGGER Persistence, Staging, and C2 Activity

# Description
This detection identifies additional indicators of compromise (IOCs) from the Elastic Security Labs report on BRUSHWORM and BRUSHLOGGER. These secondary behaviors include the creation of specific scheduled tasks (MSGraphics and MSRecorder) used for persistence and execution of the side-loaded DLLs. It also detects the unique data staging directory (C:\Users\Public\Systeminfo\) and the exfiltration hash tracking file (hashconfig in the NuGet directory). Finally, it includes a network query to identify communication with the known command-and-control (C2) server and the specific URI used to download the DLL payload (/updtdll).

# References
- https://www.elastic.co/security-labs/brushworm-targets-financial-services

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- BRUSHWORM (Backdoor / Worm)
- BRUSHLOGGER (Keylogger)

# MITRE ATT&CK
- T1053.005: Scheduled Task/Job: Scheduled Task
- T1074.001: Data Staged: Local Data Staging
- T1071.001: Application Layer Protocol: Web Protocols
- T1574.002: Hijack Execution Flow: DLL Side-Loading

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceNetworkEvents

# Query
## Query 3 - BRUSHWORM Network C2 Communication
This query hunts for the network communication patterns used by the backdoor to download modular payloads. It checks for connections to the specific C2 domain resources.dawnnewsisl[.]com or HTTP GET requests to the /updtdll URI.

```kql
// let DeviceNetworkEvents = datatable(
//     Timestamp: datetime,
//     DeviceId: string,
//     DeviceName: string,
//     ActionType: string,
//     RemoteIP: string,
//     RemoteUrl: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string,
//     InitiatingProcessAccountName: string
// )
// [
//     // Case 1: BRUSHWORM downloading DLL payload via HTTP
//     datetime(2026-03-27 12:00:00), "device-guid-1", "Finance-WKST1", "HttpConnectionInspected", "192.168.1.100", "https://resources.dawnnewsisl.com/updtdll", "brushworm.exe", "brushworm.exe", "SYSTEM",
//     // Case 2: Connection to malicious domain via DNS/Network
//     datetime(2026-03-27 12:05:00), "device-guid-2", "Finance-WKST2", "ConnectionSuccess", "192.168.1.100", "resources.dawnnewsisl.com", "brushworm.exe", "brushworm.exe", "SYSTEM",
//     // Case 3: Legitimate connection (should not trigger)
//     datetime(2026-03-27 12:10:00), "device-guid-3", "Finance-WKST3", "ConnectionSuccess", "10.0.0.5", "www.microsoft.com", "msedge.exe", "msedge.exe", "jdoe"
// ];
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType in~ ("ConnectionSuccess", "HttpConnectionInspected", "DnsConnectionInspected")
| where RemoteUrl has "dawnnewsisl.com" or RemoteUrl has "/updtdll"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
