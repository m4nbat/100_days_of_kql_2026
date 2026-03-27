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
- T1562.001: Impair Defenses: Disable or Modify Tools
- T1112: Modify Registry

# Data Sources
- Microsoft Defender XDR / Microsoft Sentinel
   - DeviceRegistryEvents

# Query
## Query 3 - Impair Defenses: Windows Defender Registry Tampering
Detects registry modifications associated with disabling Windows Defender features, specifically Real-Time Behavior Monitoring (DisableBehaviorMonitoring) and automatic sample submission to Microsoft (SubmitSamplesConsent), both of which are targeted by BlankGrabber.

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
//     // Case 1: BlankGrabber disabling behavior monitoring
//     datetime(2026-03-27 12:00:00), "Workstation01", "RegistryValueSet", @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", "1", "pythonw.exe", "pythonw.exe main.pyc", "SYSTEM",
//     // Case 2: BlankGrabber disabling sample submission consent
//     datetime(2026-03-27 12:05:00), "Workstation02", "RegistryValueSet", @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SubmitSamplesConsent", "0", "cmd.exe", "cmd.exe /c reg add ...", "SYSTEM"
// ];
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has "Windows Defender"
| where (RegistryValueName =~ "DisableBehaviorMonitoring" and RegistryValueData == "1")
   or (RegistryValueName =~ "SubmitSamplesConsent" and RegistryValueData == "0")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
