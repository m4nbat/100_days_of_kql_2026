# Name
North Korea UNC1069/UNC4899 WAVESHAPER.V2: Detecting Malicious NPM Package Versions (Installation)

# Description
Detects the actual installation command for the specific compromised versions of axios. This assumes the install command is captured in the logs.

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
- T1195.002 - Supply Chain Compromise: Compromise Software Dependencies
- T1059.007 - Command and Scripting Interpreter: JavaScript

# Data Sources
- Microsoft Defender XDR
  - DeviceProcessEvents

# Query
## Query 4: Detecting Malicious NPM Package Versions (Installation)
Detects the actual installation command for the specific compromised versions of axios. This assumes the install command is captured in the logs.

```kql
// Testing datatable for logic validation
let DeviceProcessEvents = datatable(
    Timestamp: datetime,
    DeviceName: string,
    ProcessCommandLine: string,
    FileName: string
)
[
    datetime(2026-03-31 13:00:00), "Workstation05", "npm install axios@1.14.1", "npm",
    datetime(2026-03-31 13:05:00), "Workstation05", "yarn add axios@0.30.4", "yarn"
];
// Detection Logic
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("npm", "yarn", "pnpm")
| where ProcessCommandLine has "axios"
| where ProcessCommandLine has_any ("1.14.1", "0.30.4")
| project Timestamp, DeviceName, ProcessCommandLine
```
