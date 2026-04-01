# Name
North Korea UNC1069/UNC4899 WAVESHAPER.V2: C2 Network Beaconing Frequency (Anomaly Variation)

# Description
Using make-series as recommended in the Definitive Guide to KQL to identify spikes in network connections to the identified C2 infrastructure. This helps differentiate between a one-off install and active beaconing.

# References
- https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package
- https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/
- https://kudelskisecurity.com/research-blog

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- UNC1069
- UNC4899
- WAVESHAPER.V2

# MITRE ATT&CK
- T1071.001 - Application Layer Protocol: Web Protocols
- T1571 - Non-Standard Port
- T1102 - Web Service

# Data Sources
- Microsoft Defender XDR
  - DeviceNetworkEvents

# Query
## Query 3: C2 Network Beaconing Frequency (Anomaly Variation)
Using make-series as recommended in the Definitive Guide to KQL to identify spikes in network connections to the identified C2 infrastructure. This helps differentiate between a one-off install and active beaconing.

```kql
// Testing datatable for logic validation
let DeviceNetworkEvents = datatable(
    Timestamp: datetime,
    DeviceName: string,
    RemoteUrl: string,
    RemoteIP: string
)
[
    datetime(2026-03-31 12:00:00), "DevBox", "sfrclak.com", "142.11.206.73",
    datetime(2026-03-31 12:10:00), "DevBox", "sfrclak.com", "142.11.206.73"
];
// Detection Logic
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "sfrclak.com" or RemoteIP == "142.11.206.73"
| make-series ConnectionCount=count() on Timestamp from ago(7d) to now() step 1h by DeviceName
| render timechart
```
