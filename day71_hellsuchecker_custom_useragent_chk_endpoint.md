# Name
HellsUchecker & ClickFix (EtherHiding) - Custom User-Agent "myApp v1.0" & /chk Endpoint

# Description
These queries are designed to identify the Tactics, Techniques, and Procedures (TTPs) associated with the HellsUchecker malware and the ClickFix/EtherHiding campaign. This detection focuses on identifying custom User-Agent strings pointing to /chk endpoints in proxy logs.

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
- T1105 - Ingress Tool Transfer

# Data Sources
- Microsoft Sentinel
   - CommonSecurityLog (Proxy/Firewall Logs)

# Query
## Query 2: Network - Custom User-Agent "myApp v1.0" & /chk Endpoint (Sentinel Proxy Logs)

```kql
// Let statement for testing the query logic
let CommonSecurityLog = datatable(
    TimeGenerated: datetime,
    DeviceVendor: string,
    DeviceAction: string,
    SourceIP: string,
    DestinationIP: string,
    DestinationPort: int,
    RequestURL: string,
    RequestClientApplication: string
)
[
    // Case 1: HellsUchecker C2 Check-in via Proxy Logs
    datetime(2024-03-12 11:00:00), "Zscaler", "Allowed", "10.0.0.15", "192.0.2.50", 443, 
    "https://c2-domain.com/chk", "myApp v1.0",

    // Case 2: Normal web browsing
    datetime(2024-03-12 11:05:00), "Zscaler", "Allowed", "10.0.0.22", "198.51.100.20", 443, 
    "https://www.google.com/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
];
// Detection Query
// Note: This query targets Microsoft Sentinel proxy data where HTTP User-Agent fields are available.
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where RequestClientApplication has "myApp v1.0" or RequestURL endswith "/chk"
| project TimeGenerated, DeviceVendor, DeviceAction, SourceIP, DestinationIP, DestinationPort, RequestURL, RequestClientApplication
```
