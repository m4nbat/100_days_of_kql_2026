# Name
Fake BSOD / ClickFix (PHALT#BLYX) Infection Chain

# Description
Detects the behavioral sequence associated with the "Fake BSOD" (ClickFix) social engineering campaign. The attack begins with a browser-based fake crash screen that tricks users into executing a malicious PowerShell command via the Run dialog. This command downloads a .proj file to a temporary location (often C:\ProgramData\) and executes it using the legitimate msbuild.exe utility (T1127.001) to bypass defenses. The payload is often associated with DCRat/DarkCrystal RAT.

# References
- https://www.knowyouradversary.ru/2026/01/367-adversaries-use-fake-bsod-to-make.html
- https://www.securonix.com/blog/analyzing-phaltblyx-how-fake-bsods-and-trusted-build-tools-are-used-to-construct-a-malware-infection/

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- PHALT#BLYX
- DCRat (DarkCrystal RAT)
- FakeSG / ClickFix

# MITRE ATT&CK
- T1204.004 (User Execution: Malicious File)
- T1127.001 (Trusted Developer Utilities Proxy Execution: MSBuild)
- T1059.001 (Command and Scripting Interpreter: PowerShell)
- T1218.011 (Signed Binary Proxy Execution: Rundll32 - variant)

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents
  - DeviceNetworkEvents
  - DeviceFileEvents
- Microsoft Sentinel
  - SecurityEvent

# Query

## Query 1: Suspicious MSBuild Execution of .proj Files
Detects the specific execution chain where msbuild.exe is used to build/run a project file located in suspicious directories like ProgramData, which is a key indicator of this campaign.

```kql
DeviceProcessEvents
| where FileName =~ "msbuild.exe"
// The campaign often saves the malicious project file as single-letter names or 'v.proj' in ProgramData
| where ProcessCommandLine has_any ("v.proj", ".proj") 
| where ProcessCommandLine has_any (@":\ProgramData\", @":\Users\Public\", @":\Temp\")
// Filter out likely legitimate build activities (e.g., from Visual Studio directories)
| where not (ProcessCommandLine has "Visual Studio" or (InitiatingProcessFileName in~ ("devenv.exe", "tfsbuildagent.exe")) 
```

## Query 2: PowerShell Download and Execute (ClickFix Pattern)
Detects the specific PowerShell command pattern pasted by the victim, which downloads the project file and immediately executes it. The pattern often includes Start-Process (or start), Invoke-WebRequest (or iwr), and execution of msbuild.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
// Look for the specific sequence: Start browser/site -> Download file -> Run MSBuild
| where ProcessCommandLine has_all ("start", "http", "iwr", "msbuild")

// Then run this filter on any unexpected hits
DeviceProcessEvents
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
// Specific indicators from the report
| where ProcessCommandLine has_all ("filter","msbuild.exe") 
   or ProcessCommandLine has "$env:ProgramData" 
   or ProcessCommandLine has "-o $env:ProgramData\\v.proj"
```

## Query 3: Browser Spawning Suspicious Child Processes (Heuristic)
Detects when a web browser process spawns powershell.exe or cmd.exe directly, which is highly abnormal for standard browsing and indicates the "Run dialog" abuse or similar browser-based exploit vectors.

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "msbuild.exe")
// Refine: The Fake BSOD attack often involves the user manually running the command, so the parent might be 'explorer.exe' (Run dialog). 
// However, if the attack evolves to drive-by or if the browser launches the terminal directly:
| where not(ProcessCommandLine has_any ("native-messaging-host", "extension")) // Filter out legitimate browser extensions
```

## Query 4: Creation of Malicious Project Files
Detects the creation of the specific .proj payload file on disk.

```kql
// Microsoft Defender for Endpoint (Advanced Hunting)
DeviceFileEvents
| where FolderPath has "ProgramData" or FolderPath has @"Users\Public"
| where FileName endswith ".proj"
// The specific file name mentioned in intelligence
| where FileName =~ "v.proj" or FileName =~ "update.proj"
```
