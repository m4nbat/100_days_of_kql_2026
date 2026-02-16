# Name
Prometei Botnet - Process and File Indicators

# Description
This detection identifies host-based indicators associated with the Prometei Botnet. Prometei is a modular botnet that utilizes a variety of techniques including "living-off-the-land" binaries (LOLBins), proprietary cryptomining modules, and credential theft tools.

The detection focuses on:
- Unique File Indicators: Presence of the specific XOR key file (mshlpda32.dll) required for payload unpacking, and known payload names (zsvc.exe, sqhost.exe).
- Suspicious Paths: Execution or file creation in the staging directory C:\Windows\Dell\.

This query checks for the creation or execution of files specifically named in the Prometei attack chain (mshlpda32.dll, sqhost.exe, zsvc.exe) and looks for activity in the known staging folder C:\Windows\Dell.

# References
- https://www.esentire.com/blog/tenant-from-hell-prometeis-unauthorized-stay-in-your-windows-server

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- Prometei Botnet

# MITRE ATT&CK
- T1059.003: Command and Scripting Interpreter: Windows Command Shell
- T1027: Obfuscated Files or Information

# Data Sources
- Microsoft Defender for Endpoint
  - DeviceProcessEvents
  - DeviceFileEvents

# Query

```kql
let SuspiciousFiles = dynamic(["mshlpda32.dll", "sqhost.exe", "zsvc.exe", "rdpcIip.exe", "netdefender.exe"]);
let SuspiciousFolders = dynamic(["C:\\Windows\\Dell"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName has_any (SuspiciousFiles)) 
     or (FolderPath has_any (SuspiciousFolders))
     or (ProcessCommandLine has "mshlpda32.dll")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, AccountName, InitiatingProcessFileName, SHA256
```
