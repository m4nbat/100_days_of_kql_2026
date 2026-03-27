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
   - DeviceFileEvents

# Query
## Query 1 - BlankGrabber Encrypted Payload Drop (blank.aes)
This query detects the file creation event of blank.aes. BlankGrabber uses PyInstaller to bundle its Python environment, and upon execution, it extracts an AES-CTR encrypted data blob named blank.aes that contains the actual malicious payload to be decrypted in memory.

```kql
// let DeviceFileEvents = datatable(
//     Timestamp: datetime,
//     DeviceName: string,
//     ActionType: string,
//     FileName: string,
//     FolderPath: string,
//     InitiatingProcessAccountName: string,
//     InitiatingProcessFileName: string,
//     InitiatingProcessCommandLine: string,
//     SHA256: string
// )
// [
//     // Case 1: BlankGrabber PyInstaller dropping blank.aes
//     datetime(2026-03-27 10:00:00), "Workstation01", "FileCreated", "blank.aes", @"C:\Users\victim\AppData\Local\Temp\_MEI12345\blank.aes", "victim", "update_utility.exe", "update_utility.exe", "e3b0c442...",
//     // Case 2: Another PyInstaller drop in a different directory
//     datetime(2026-03-27 10:05:00), "Workstation02", "FileCreated", "blank.aes", @"C:\ProgramData\blank.aes", "SYSTEM", "malicious.exe", "malicious.exe", "a5b3c2d1...",
//     // Case 3: Legitimate file (should not trigger)
//     datetime(2026-03-27 10:10:00), "Workstation03", "FileCreated", "config.aes", @"C:\Program Files\App\config.aes", "jdoe", "app.exe", "app.exe", "b2c3d4e5..."
// ];
DeviceFileEvents
| where Timestamp > ago(14d) // Filter early for performance
| where ActionType in~ ("FileCreated", "FileRenamed", "FileModified")
| where FileName =~ "blank.aes"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```
