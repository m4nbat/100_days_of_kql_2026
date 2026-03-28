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
   - DeviceProcessEvents

# Query
## Query 1 - CTRL Framework: .NET LOLBin Execution
This query monitors for the execution of common Windows LOLBins frequently abused by .NET access frameworks to compile, load, or execute malicious .NET payloads while evading traditional defenses.

```kql
// let DeviceProcessEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     FileName: string,
//     FolderPath: string,
//     ProcessCommandLine: string,
//     AccountName: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string
// )
// [
//     // Case 1: MSBuild compiling/executing an anomalous .csproj or .xml file
//     datetime(2026-03-28 10:00:00), "Workstation01", "ProcessCreated", "MSBuild.exe", @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe", "MSBuild.exe C:\\Temp\\payload.xml", "victim", "cmd.exe", "cmd.exe /c start MSBuild.exe",
//     // Case 2: RegAsm used to execute a .NET assembly bypass
//     datetime(2026-03-28 10:05:00), "Workstation02", "ProcessCreated", "RegAsm.exe", @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe", "RegAsm.exe /U C:\\Users\\Public\\ctrl_module.dll", "victim", "powershell.exe", "powershell.exe",
//     // Case 3: Legitimate developer build (should be tuned out or investigated contextually)
//     datetime(2026-03-28 10:10:00), "Workstation03", "ProcessCreated", "MSBuild.exe", @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe", "MSBuild.exe C:\\Dev\\Project\\app.sln", "jdoe", "devenv.exe", "devenv.exe"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d) // Filter early for performance
| where ActionType == "ProcessCreated"
| where FileName in~ ("MSBuild.exe", "RegAsm.exe", "RegSvcs.exe", "InstallUtil.exe", "csc.exe", "jsc.exe", "vbc.exe")
// Look for execution from unexpected paths like Temp, Public, or AppData, or unusual extensions
| where ProcessCommandLine has_any (@"\Temp\", @"\Users\Public\", @"\AppData\Local\Temp\")
   or ProcessCommandLine endswith ".xml"
   or ProcessCommandLine endswith ".txt"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
