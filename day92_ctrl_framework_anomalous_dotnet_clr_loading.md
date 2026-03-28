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
   - DeviceImageLoadEvents

# Query
## Query 2 - CTRL Framework: Anomalous .NET CLR Loading
Advanced .NET access frameworks often inject into unmanaged processes (like notepad.exe or svchost.exe) and load the .NET Common Language Runtime (clr.dll or mscoree.dll) to execute modules entirely in memory. This query detects native processes unexpectedly loading .NET runtime DLLs.

```kql
// let DeviceImageLoadEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     FileName: string,
//     FolderPath: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string,
//     InitiatingProcessAccountName: string
// )
// [
//     // Case 1: Unmanaged process (Notepad) loading the .NET CLR (Execute-Assembly injection)
//     datetime(2026-03-28 11:00:00), "Workstation01", "ImageLoaded", "clr.dll", @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll", "notepad.exe", "notepad.exe", "victim",
//     // Case 2: WMI Provider Host anomalously loading .NET core
//     datetime(2026-03-28 11:05:00), "Workstation02", "ImageLoaded", "mscoree.dll", @"C:\Windows\System32\mscoree.dll", "wmiprvse.exe", "wmiprvse.exe", "SYSTEM",
//     // Case 3: Legitimate .NET application loading the CLR (should not trigger)
//     datetime(2026-03-28 11:10:00), "Workstation03", "ImageLoaded", "clr.dll", @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll", "powershell.exe", "powershell.exe", "jdoe"
// ];
DeviceImageLoadEvents
| where Timestamp > ago(14d)
| where ActionType == "ImageLoaded"
| where FileName in~ ("clr.dll", "mscoree.dll", "mscorlib.dll")
// Define a list of native Windows binaries that do not typically host .NET assemblies
| where InitiatingProcessFileName in~ (
    "notepad.exe",
    "svchost.exe",
    "explorer.exe",
    "cmd.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "lsass.exe",
    "spoolsv.exe",
    "wmiprvse.exe"
)
| project Timestamp, DeviceName, ActionType, LoadedImage = FileName, ImagePath = FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
