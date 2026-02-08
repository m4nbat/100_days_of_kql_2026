# RedKitten Campaign - SloppyMIO Infection Chain & TTPs

# Description
Detects techniques and behaviors associated with the RedKitten campaign (SloppyMIO backdoor). This includes malicious Excel macro activity, the abuse of the legitimate AppVStreamingUX.exe binary (likely for DLL side-loading or evasion) running from non-standard paths, and C2 communication attempting to reach Telegram, GitHub, or Google Drive from suspicious processes.

# References
- https://harfanglab.io/insidethelab/redkitten-ai-accelerated-campaign-targeting-iranian-protests/

# Author
M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- RedKitten
- SloppyMIO
- Yellow Liderc (Imperial Kitten)

# MITRE ATT&CK
- T1566.001 - Phishing: Spearphishing Attachment
- T1059.005 - Command and Scripting Interpreter: Visual Basic
- T1036.005 - Masquerading: Match Legitimate Name or Location
- T1102.002 - Web Service: Bidirectional Communication
- T1071.001 - Application Layer Protocol: Web Protocols

# Data Sources
- Microsoft Defender for Endpoint
- DeviceProcessEvents
- DeviceNetworkEvents
- DeviceFileEvents
- Microsoft Sentinel
- SecurityEvent (Windows)

# Detection Queries

## Query 1 — Suspicious AppVStreamingUX Execution (Defender)
Detects AppVStreamingUX.exe running from non-standard locations, indicative of copying for DLL sideloading or evasion.

```kql
DeviceProcessEvents
| where FileName =~ "AppVStreamingUX.exe"
// Filter out legitimate locations for App-V
| where not(FolderPath has_any (
    @":\Program Files\Microsoft App-V",
    @":\Program Files (x86)\Microsoft App-V",
    @":\Windows\System32",
    @":\Windows\SysWOW64"
))
// RedKitten often places this in Temp, ProgramData, or User Profile hidden folders
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

## Query 2 — Telegram or GitHub C2 Traffic from Non-Browser (Defender)
Looks for network connections to Telegram, raw GitHub content, or Google Drive initiated by non-browser processes, with emphasis on AppVStreamingUX.exe as a suspect initiator.

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("api.telegram.org", "raw.githubusercontent.com", "drive.google.com")
// Filter out standard browsers to reduce noise
| where not(InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe", "safari.exe","msedgewebview2.exe"))
// High fidelity: Check if the abused binary is the one calling out
| extend IsSloppyMIO_Suspect = iff(InitiatingProcessFileName =~ "AppVStreamingUX.exe", true, false)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath, IsSloppyMIO_Suspect
| sort by IsSloppyMIO_Suspect desc
```

## Query 3 — Office Application Dropping Executables (Defender)
Detects Office apps (Excel/Word/PowerPoint) creating executables or the specific AppVStreamingUX.exe, which indicates macro-driven payload drops.

```kql
DeviceFileEvents
| where InitiatingProcessFileName in~ ("excel.exe", "winword.exe", "powerpnt.exe")
| where ActionType == "FileCreated"
// Look for the specific binary abused by RedKitten or generic executable writes
| where FileName =~ "AppVStreamingUX.exe" or FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr"
// Filter out common temp files if necessary, though .exe creation by Excel is almost always suspicious
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, SHA256
```

## Query 4: DeviceEvents (ScheduledTaskCreated)
This query utilizes the ScheduledTaskCreated ActionType within DeviceEvents. This event provides visibility into the task definition itself, allowing us to inspect the command being registered.

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ScheduledTaskCreated"
// Filter for the specific binary abused by RedKitten
| where AdditionalFields has "AppVStreamingUX.exe"
// Filter out legitimate App-V paths to reduce false positives
| where not(AdditionalFields has_any (
    "Program Files\\Microsoft App-V", 
    "Program Files (x86)\\Microsoft App-V",
    "Windows\\System32"
))
| extend TaskName = tostring(parse_json(AdditionalFields).TaskName)
| extend Command = tostring(parse_json(AdditionalFields).Command)
| project Timestamp, DeviceName, ActionType, TaskName, Command, InitiatingProcessFileName, AdditionalFields
```
## Query 5 - DeviceProcessEvents (Schtasks Command Line)
This query looks for the execution of schtasks.exe used to create the malicious task. This is useful if the specific ScheduledTaskCreated event is missed or for correlating the process that established the persistence.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
// Look for task creation commands
| where ProcessCommandLine has "/create"
// Look for the abused binary in the arguments
| where ProcessCommandLine has "AppVStreamingUX.exe"
// Ensure we are detecting usage outside of standard paths
| where not(ProcessCommandLine has_any (
    "Program Files\\Microsoft App-V", 
    "Program Files (x86)\\Microsoft App-V",
    "Windows\\System32"
))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
```

# Engineering & Performance Notes
- Filtering early by `FileName` or `RemoteUrl` reduces scan volume in high-throughput tables (DeviceProcessEvents/DeviceNetworkEvents).
- Use allowlists for known enterprise-approved paths if AppVStreamingUX is legitimately used in your environment.
- Joining DeviceFileEvents with DeviceFileCertificateInfo or DeviceImageLoadEvents can help validate signer and loading context.

# Investigation Steps
If detections surface:
- Inspect the origin archive or email for spearphishing indicators (sender, message, attachment history).
- Retrieve the file hashes and check VirusTotal/other telemetry. Join with `DeviceFileEvents` for prevalence.
- Examine parent/initiating process lineage. Macro-enabled Office spawning cmd/PowerShell and writing AppVStreamingUX.exe or other exes is high priority.
- If network C2 is seen to Telegram/GitHub/Drive, capture full URLs and request logs for content and temporal patterns.
- Search for scheduled tasks or other persistence mechanisms referencing the abused binary.

----------- Template End --------------
