# Name
CTRL Framework: Advanced Evasion, Fileless Staging, and Persistence

# Description
This detection suite expands on the indicators and behaviors associated with the previously undocumented "CTRL" Russian .NET access framework. Advanced .NET frameworks typically minimize their footprint on disk to evade traditional antivirus software, heavily favoring in-memory execution and registry-based storage.

These additional queries focus on:
- **Fileless Payload Staging**: Detecting the storage of large, Base64-encoded PE files (like .NET assemblies) directly within the Windows Registry.
- **LOLBin Post-Exploitation Activity**: Identifying when typical .NET Living-off-the-Land Binaries (LOLBins) are used to spawn secondary discovery or execution tools (e.g., command shells), indicating that the framework has successfully loaded and is executing commands.
- **WMI Persistence Execution**: Hunting for the Windows Management Instrumentation Provider Host (wmiprvse.exe) anomalously spawning .NET compilation or execution binaries, a common technique for establishing stealthy, fileless persistence.

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
- T1546.003: Event Triggered Execution: Windows Management Instrumentation Event Subscription
- T1027.011: Obfuscated Files or Information: Fileless Storage
- T1059: Command and Scripting Interpreter
- T1218: System Binary Proxy Execution

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceRegistryEvents

# Query
## Query 1 - CTRL Framework: Fileless .NET Assembly Staging in Registry
Advanced threat actors often bypass disk-based detections by saving their encrypted or encoded .NET assemblies directly into the Windows Registry. This query hunts for abnormally large registry values or known Base64 headers for executable files (e.g., TVqQ for the MZ header) being written by script interpreters or .NET LOLBins.

```kql
// let DeviceRegistryEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     RegistryKey: string,
//     RegistryValueName: string,
//     RegistryValueData: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string,
//     InitiatingProcessAccountName: string
// )
// [
//     // Case 1: Base64 MZ Header written to registry for fileless staging
//     datetime(2026-03-28 10:00:00), "Workstation01", "RegistryValueSet", @"HKEY_CURRENT_USER\Software\Classes\AppX\Config", "Payload", "TVqQAAMAAAAEAAAA//8AALgAAAA...", "powershell.exe", "powershell.exe -c ...", "victim",
//     // Case 2: Abnormally large registry payload written by a LOLBin
//     datetime(2026-03-28 10:05:00), "Workstation02", "RegistryValueSet", @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "UpdateCache", "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAA...<2000+ chars>", "msbuild.exe", "msbuild.exe /nologo payload.csproj", "victim",
//     // Case 3: Normal small registry write (should not trigger)
//     datetime(2026-03-28 10:10:00), "Workstation03", "RegistryValueSet", @"HKEY_CURRENT_USER\Software\App\Settings", "Theme", "Dark", "explorer.exe", "explorer.exe", "jdoe"
// ];
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where ActionType == "RegistryValueSet"
// Focus on writes by script interpreters and known .NET LOLBins
| where InitiatingProcessFileName in~ (
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe",
    "msbuild.exe", "csc.exe", "vbc.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe",
    "mshta.exe"
)
// Detect Base64-encoded MZ/PE headers (TVqQ = base64 of 'MZ\x90\x00') or large blobs that may be encoded assemblies
| where RegistryValueData startswith "TVqQ"
    or RegistryValueData startswith "TVpQ"
    or strlen(RegistryValueData) > 1000
| project
    Timestamp,
    DeviceName,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData = substring(RegistryValueData, 0, 200),  // Truncate for readability
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
```
