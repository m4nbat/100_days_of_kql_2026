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
- T1140: Deobfuscate/Decode Files or Information
- T1027: Obfuscated Files or Information
- T1059.006: Command and Scripting Interpreter: Python

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceProcessEvents

# Query
## Query 1 - BlankGrabber Certutil Decode: Rust Stager Decoding
BlankGrabber uses certutil.exe to decode an obfuscated Rust-based stager from disk. The -decode flag is abused to convert a Base64-encoded certificate file into a runnable executable, allowing the malware to stage its next-phase payload without downloading additional files from the internet. This query detects the use of certutil.exe with the -decode or /decode argument, which is rarely legitimate outside of specific administrative contexts.

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
//     // Case 1: BlankGrabber decoding its Rust stager
//     datetime(2026-03-27 10:00:00), "Workstation01", "ProcessCreated", "certutil.exe", "certutil.exe -decode C:\\Temp\\cert.txt C:\\Temp\\stager.exe", "victim", "cmd.exe", "cmd.exe /c install.bat",
//     // Case 2: Legitimate admin downloading a file (should not trigger)
//     datetime(2026-03-27 10:05:00), "Workstation02", "ProcessCreated", "certutil.exe", "certutil.exe -urlcache -split -f https://internal/config.xml", "admin", "powershell.exe", "powershell.exe"
// ];
DeviceProcessEvents
| where Timestamp > ago(14d) // Filter early for performance
| where ActionType == "ProcessCreated"
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has "-decode" or ProcessCommandLine has "/decode"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
