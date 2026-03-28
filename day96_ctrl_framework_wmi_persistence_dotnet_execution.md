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
   - DeviceProcessEvents

# Query
## Query 3 - CTRL Framework: WMI Persistence via .NET Compiler/Execution Binaries
A reliable indicator of fileless WMI-based persistence is the Windows Management Instrumentation Provider Host (wmiprvse.exe) spawning .NET compilation or execution tools. This query hunts for wmiprvse.exe acting as the parent process for known .NET LOLBins, which would indicate that a WMI Event Subscription is being used to trigger a .NET-based payload on an event such as system startup or user logon.

```kql
// let DeviceProcessEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     FileName: string,
//     ProcessCommandLine: string,
//     AccountName: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string
// )
// [
//     // Case 1: WMI persistence triggering InstallUtil to load a .NET assembly
//     datetime(2026-03-28 12:00:00), "Workstation01", "ProcessCreated", "installutil.exe", "installutil.exe /logfile= /LogToConsole=false C:\\ProgramData\\upd.dll", "SYSTEM", "wmiprvse.exe", "wmiprvse.exe",
//     // Case 2: WMI persistence triggering MSBuild with an in-memory project
//     datetime(2026-03-28 12:05:00), "Workstation02", "ProcessCreated", "msbuild.exe", "msbuild.exe /nologo C:\\Users\\Public\\task.csproj", "SYSTEM", "wmiprvse.exe", "wmiprvse.exe",
//     // Case 3: WMI persistence triggering csc.exe to compile a C# payload
//     datetime(2026-03-28 12:10:00), "Workstation03", "ProcessCreated", "csc.exe", "csc.exe /out:C:\\Windows\\Temp\\svc.exe C:\\Windows\\Temp\\svc.cs", "SYSTEM", "wmiprvse.exe", "wmiprvse.exe",
//     // Case 4: Normal WMI operation (should not trigger)
//     datetime(2026-03-28 12:15:00), "Workstation04", "ProcessCreated", "msiexec.exe", "msiexec.exe /i update.msi /quiet", "SYSTEM", "wmiprvse.exe", "wmiprvse.exe"
// ];
let DotNetLolBins = dynamic([
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "msbuild.exe",
    "csc.exe",
    "vbc.exe",
    "jsc.exe",
    "ilasm.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
// WMI Provider Host is the parent — indicates WMI Event Subscription trigger
| where InitiatingProcessFileName =~ "wmiprvse.exe"
// Child process is a .NET compilation or execution LOLBin
| where FileName in~ (DotNetLolBins)
| project
    Timestamp,
    DeviceName,
    AccountName,
    ActionType,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
```
