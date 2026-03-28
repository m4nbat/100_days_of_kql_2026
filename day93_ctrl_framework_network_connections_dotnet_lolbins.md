# Name
CTRL Framework: .NET Access Framework Activity

# Description
This detection suite focuses on identifying behaviors associated with the "CTRL" framework, a previously undocumented Russian .NET-based access framework detailed by Censys. Threat actors often use .NET frameworks for initial access, staging, and post-exploitation due to the ease of loading modules directly into memory and bypassing traditional disk-based detections.
These queries detect common .NET framework tradecraft, including:
The execution of .NET payloads via Living off the Land Binaries (LOLBins) such as MSBuild.exe, RegAsm.exe, or InstallUtil.exe.
The injection or anomalous loading of the .NET Common Language Runtime (CLR) components (clr.dll, mscoree.dll) into unmanaged or unexpected processes, indicative of techniques like Execute-Assembly or reflective DLL loading.
Suspicious network beaconing and Command and Control (C2) communication originating from these abused .NET binaries.

# References
- https://censys.com/blog/under-ctrl-dissecting-a-previously-undocumented-russian-net-access-framework/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- CTRL Framework (.NET Access Framework)
- Russian Nexus Threat Actors

# MITRE ATT&CK
- T1218: System Binary Proxy Execution
- T1055: Process Injection
- T1105: Ingress Tool Transfer
- T1071.001: Application Layer Protocol: Web Protocols

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceNetworkEvents

# Query
## Query 3 - CTRL Framework: Network Connections from .NET LOLBins
This query monitors for outbound network connections initiated by .NET LOLBins. Under normal circumstances, tools like RegAsm.exe or InstallUtil.exe do not require internet access. If they are used by the CTRL framework to establish C2 communication or download secondary payloads, this query will flag the anomaly.

```kql
// let DeviceNetworkEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     RemoteIP: string,
//     RemoteUrl: string,
//     RemotePort: int,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string,
//     InitiatingProcessAccountName: string
// )
// [
//     // Case 1: RegAsm beaconing to a C2 server
//     datetime(2026-03-28 12:00:00), "Workstation01", "ConnectionSuccess", "192.168.50.100", "c2.malicious-domain.com", 443, "RegAsm.exe", "RegAsm.exe /U C:\\Users\\Public\\ctrl.dll", "victim",
//     // Case 2: MSBuild downloading a payload
//     datetime(2026-03-28 12:05:00), "Workstation02", "HttpConnectionInspected", "203.0.113.50", "payload-delivery.net", 80, "MSBuild.exe", "MSBuild.exe C:\\Temp\\build.xml", "SYSTEM",
//     // Case 3: Legitimate browser traffic (should not trigger)
//     datetime(2026-03-28 12:10:00), "Workstation03", "ConnectionSuccess", "10.0.0.5", "www.microsoft.com", 443, "msedge.exe", "msedge.exe", "jdoe"
// ];
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType in~ ("ConnectionSuccess", "HttpConnectionInspected", "DnsConnectionInspected")
// Target native .NET LOLBins that should rarely initiate external network requests
| where InitiatingProcessFileName in~ ("MSBuild.exe", "RegAsm.exe", "RegSvcs.exe", "InstallUtil.exe", "csc.exe", "jsc.exe", "vbc.exe")
// Exclude typical local network traffic to minimize noise
| where RemoteIP !startswith "10." and RemoteIP !startswith "127." and RemoteIP !startswith "169.254."
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
