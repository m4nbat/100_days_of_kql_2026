# Name
HellsUchecker & ClickFix (EtherHiding) - Finger.exe Outbound on Port 79

# Description
These queries are designed to identify the Tactics, Techniques, and Procedures (TTPs) associated with the HellsUchecker malware and the ClickFix/EtherHiding campaign. This detection focuses on identifying network anomalies such as finger.exe outbound communication on port 79.

# References
- https://www.derp.ca/research/hellsuchecker-clickfix-etherhiding/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- HellsUchecker
- ClickFix
- EtherHiding

# MITRE ATT&CK
- T1071.001 - Application Layer Protocol: Web Protocols

# Data Sources
- Microsoft Defender XDR
   - DeviceNetworkEvents

# Query
## Query 1: Network - Finger.exe Outbound on Port 79

```kql
// Let statement for testing the query logic
let DeviceNetworkEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    ActionType: string,
    InitiatingProcessFileName: string,
    InitiatingProcessCommandLine: string,
    RemoteIP: string,
    RemotePort: int,
    RemoteUrl: string
)
[
    // Case 1: Suspicious finger.exe outbound to port 79
    datetime(2024-03-12 10:15:30), "device-guid-1", "Workstation01.contoso.com", "ConnectionSuccess", 
    "finger.exe", "finger.exe @malicious-c2.com", "198.51.100.5", 79, "malicious-c2.com",
    
    // Case 2: Standard web traffic
    datetime(2024-03-12 10:20:00), "device-guid-2", "Workstation02.contoso.com", "ConnectionSuccess", 
    "msedge.exe", "msedge.exe", "203.0.113.10", 443, "www.microsoft.com"
];
// Detection Query
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "finger.exe"
| where RemotePort == 79
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
```
