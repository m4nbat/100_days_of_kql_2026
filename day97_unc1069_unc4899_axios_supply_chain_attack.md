# Name
North Korea UNC1069/UNC4899 Axios Supply Chain Attack

# Description
Detects post-installation activity and persistent artifacts associated with the compromised axios npm package versions (1.14.1, 0.30.4) and its malicious dependency plain-crypto-js. The attack deploys the WAVESHAPER.V2 RAT across Windows, macOS, and Linux.

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
- T1547.001 - Pre-OS Boot: Registry Run Keys / Startup Folder
- T1105 - Ingress Tool Transfer

# Data Sources
- Microsoft Defender XDR
  - DeviceProcessEvents
  - DeviceFileEvents
  - DeviceRegistryEvents
  - DeviceNetworkEvents

# Query
## Query 1: Malicious NPM Post-Install Execution (Process Events)
This query identifies the execution of the setup.js dropper or the presence of the malicious dependency plain-crypto-js in command lines originating from npm or node.

```kql
// Testing datatable for logic validation
let DeviceProcessEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    FileName: string,
    ProcessCommandLine: string,
    InitiatingProcessFileName: string,
    AccountName: string
)
[
    datetime(2026-03-31 02:00:00), "d-123", "Dev-Workstation", "node.exe", "node node_modules/plain-crypto-js/setup.js", "npm", "j.developer",
    datetime(2026-03-31 02:15:00), "d-123", "Dev-Workstation", "sh", "sh -c node setup.js", "node", "j.developer"
];
// Detection Logic
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (ProcessCommandLine has_any("plain-crypto-js", "setup.js") and InitiatingProcessFileName has_any("npm", "node", "sh", "bash"))
   or (ProcessCommandLine has "axios" and ProcessCommandLine has_any("1.14.1", "0.30.4"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

## Query 2: WAVESHAPER.V2 Cross-Platform Artifacts (File Events)
Detects the creation of specific RAT artifacts on Windows, Linux, and macOS as described in the threat report.

```kql
// Testing datatable for logic validation
let DeviceFileEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    FileName: string,
    FolderPath: string,
    InitiatingProcessCommandLine: string
)
[
    datetime(2026-03-31 03:00:00), "d-456", "Prod-Server-Linux", "ld.py", "/tmp", "node setup.js",
    datetime(2026-03-31 03:05:00), "d-789", "Win-Laptop", "wt.exe", "C:\\ProgramData", "node setup.js"
];
// Detection Logic
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FolderPath == "/tmp" and FileName == "ld.py") // Linux
   or (FolderPath == "C:\\ProgramData" and FileName in~ ("wt.exe", "system.bat")) // Windows
   or (FolderPath == "/Library/Caches" and FileName == "com.apple.act.mond") // macOS
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessCommandLine
```

## Query 3: Registry Persistence for WAVESHAPER.V2 (Windows)
Detects the creation of the specific registry run key used by the RAT to achieve persistence on Windows systems.

```kql
// Testing datatable for logic validation
let DeviceRegistryEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    RegistryKey: string,
    RegistryValueName: string,
    RegistryValueData: string
)
[
    datetime(2026-03-31 04:00:00), "d-789", "Win-Laptop", @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "MicrosoftUpdate", @"C:\ProgramData\system.bat"
];
// Detection Logic
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName == "MicrosoftUpdate"
| where RegistryValueData has_any("wt.exe", "system.bat")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

## Query 4: C2 Communication (Network Events)
Detects network connections to the known C2 infrastructure identified in the Mandiant/Google analysis.

```kql
// Testing datatable for logic validation
let DeviceNetworkEvents = datatable(
    Timestamp: datetime,
    DeviceId: string,
    DeviceName: string,
    RemoteUrl: string,
    RemoteIP: string,
    RemotePort: int
)
[
    datetime(2026-03-31 05:00:00), "d-123", "Dev-Workstation", "sfrclak.com", "142.11.206.73", 443
];
// Detection Logic
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "sfrclak.com" or RemoteIP == "142.11.206.73"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort
```
