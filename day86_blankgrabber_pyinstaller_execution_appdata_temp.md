# Name
BlankGrabber Info Stealer Execution and C2 Activity

# Description
This detection suite identifies indicators of compromise (IOCs) and behaviors associated with BlankGrabber, a Python-based information stealer. BlankGrabber is engineered to exfiltrate sensitive data such as browser credentials, session tokens, and cryptocurrency wallets. It is often compiled into a standalone executable using PyInstaller to evade static detection.

# References
- https://www.splunk.com/en_us/blog/security/blankgrabber-trojan-stealer-analysis-detection.html

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- BlankGrabber (Information Stealer / Trojan)

# MITRE ATT&CK
- T1027: Obfuscated Files or Information
- T1071.001: Application Layer Protocol: Web Protocols
- T1552.001: Credentials In Files
- T1059.006: Command and Scripting Interpreter: Python

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceProcessEvents

# Query
## Query 3 - Suspicious PyInstaller Execution from AppData Temp
BlankGrabber operators commonly package the python script using PyInstaller. When executed, PyInstaller silently unpacks the Python interpreter and malicious bytecode (.pyc) into a dynamically generated directory named _MEI within the user's AppData\Local\Temp folder before executing it. This query flags the anomalous execution of binaries directly out of these _MEI folders.

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
//     // Case 1: BlankGrabber component executing from extracted PyInstaller Temp folder
//     datetime(2026-03-27 12:00:00), "Workstation01", "ProcessCreated", "pythonw.exe", @"C:\Users\victim\AppData\Local\Temp\_MEI88291\pythonw.exe", "pythonw.exe main.pyc", "victim", "invoice.exe", "invoice.exe",
//     // Case 2: Another PyInstaller malicious execution
//     datetime(2026-03-27 12:05:00), "Workstation02", "ProcessCreated", "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c start /b ...", "victim", "update.exe", @"C:\Users\admin\AppData\Local\Temp\_MEI11223\update.exe",
//     // Case 3: Standard application execution (should not trigger)
//     datetime(2026-03-27 12:10:00), "Workstation03", "ProcessCreated", "winword.exe", @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "winword.exe", "jdoe", "explorer.exe", "explorer.exe"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ActionType == "ProcessCreated"
// Detect processes running out of the PyInstaller extraction folder
| where FolderPath has @"\AppData\Local\Temp\_MEI" 
   or InitiatingProcessFolderPath has @"\AppData\Local\Temp\_MEI"
// Optional: You can filter out known legitimate PyInstaller apps in your environment here if necessary
// | where FileName !in~ ("legit_internal_tool.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
