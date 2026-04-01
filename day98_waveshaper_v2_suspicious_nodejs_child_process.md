# Name
North Korea UNC1069/UNC4899 WAVESHAPER.V2: Suspicious Node.js Child Process (Process Tree Anomaly)

# Description
The WAVESHAPER.V2 dropper (setup.js) uses node to spawn shell commands (Windows cmd/bat, Linux sh/py, macOS sh). This query detects unusual shells spawned by node.exe or node (Linux/macOS) within the npm node_modules directory.

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
- T1059.004 - Command and Scripting Interpreter: Unix Shell
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell

# Data Sources
- Microsoft Defender XDR
  - DeviceProcessEvents

# Query
## Query 1: Suspicious Node.js Child Process (Process Tree Anomaly)
The WAVESHAPER.V2 dropper (setup.js) uses node to spawn shell commands (Windows cmd/bat, Linux sh/py, macOS sh). This query detects unusual shells spawned by node.exe or node (Linux/macOS) within the npm node_modules directory.

```kql
// Testing datatable for logic validation
let DeviceProcessEvents = datatable(
    Timestamp: datetime,
    DeviceName: string,
    FileName: string,
    ProcessCommandLine: string,
    InitiatingProcessFileName: string,
    InitiatingProcessCommandLine: string
)
[
    datetime(2026-03-31 10:00:00), "Server01", "cmd.exe", "cmd.exe /c system.bat", "node.exe", "node node_modules/plain-crypto-js/setup.js",
    datetime(2026-03-31 10:05:00), "LinuxSrv", "sh", "sh -c python3 ld.py", "node", "node setup.js"
];
// Detection Logic
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has "node"
| where InitiatingProcessCommandLine has_any("setup.js", "plain-crypto-js")
| where FileName in~ ("cmd.exe", "sh", "bash", "python", "python3")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```
