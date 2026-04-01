# Name
North Korea UNC1069/UNC4899 WAVESHAPER.V2: Cross-Platform Dropper Persistence (File Events Variation)

# Description
WAVESHAPER.V2 places specific binaries in system/user cache folders across Windows, Linux, and macOS. This variation looks for the specific filenames and paths identified in the report.

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
- T1105 - Ingress Tool Transfer
- T1036.005 - Masquerading: Match Legitimate Name or Location

# Data Sources
- Microsoft Defender XDR
  - DeviceFileEvents

# Query
## Query 2: Cross-Platform Dropper Persistence (File Events Variation)
WAVESHAPER.V2 places specific binaries in system/user cache folders across Windows, Linux, and macOS. This variation looks for the specific filenames and paths identified in the report.

```kql
// Testing datatable for logic validation
let DeviceFileEvents = datatable(
    Timestamp: datetime,
    DeviceName: string,
    FileName: string,
    FolderPath: string,
    SHA256: string
)
[
    datetime(2026-03-31 11:00:00), "MBP-Dev", "com.apple.act.mond", "/Library/Caches", "f1a2b3c4...",
    datetime(2026-03-31 11:10:00), "Win-CI-CD", "wt.exe", "C:\\ProgramData", "e5d6c7b8..."
];
// Detection Logic
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FileName =~ "com.apple.act.mond" and FolderPath has "Caches") // macOS
   or (FileName =~ "ld.py" and FolderPath has "/tmp") // Linux
   or (FileName =~ "wt.exe" and FolderPath has "ProgramData") // Windows
   or (FileName =~ "system.bat" and FolderPath has "ProgramData") // Windows
| project Timestamp, DeviceName, FolderPath, FileName, SHA256
```
