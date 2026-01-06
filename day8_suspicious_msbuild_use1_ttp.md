# Name
Unusual use of msbuild.exe to execute code inside .proj file to bypass AV detection

# Description
Unusual use of msbuild.exe to execute code inside .proj file to bypass AV detection

<img width="1600" height="951" alt="image" src="https://github.com/user-attachments/assets/adea3f15-2dee-4a99-922b-207a973c1c2b" />

Context:
- Execute Payload:
  - It runs the msbuild.exe found in step 2.
  - Passes the downloaded malicious project file (v.proj) as an argument.
  - MSBuild compiles and executes the code inside v.proj. Because msbuild.exe is a trusted Microsoft application, this often bypasses basic application whitelisting or antivirus detection.

The v.proj file is a classic MSBuild bypass payload


# References
- https://www.bleepingcomputer.com/news/security/clickfix-attack-uses-fake-windows-bsod-screens-to-push-malware/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- ASyncRAT
- ClickFix

# MITRE ATT&CK
- Defense Evasion
- T1562 : Impair Defenses
- T1562.001 Impair Defenses: Disable or Modify Tools
- T1127.001 Trusted Developer Utilities Proxy Execution: MSBuild

# Data Sources
- MDE
  - DeviceProcessEvents

# Query

```
// source: https://www.bleepingcomputer.com/news/security/clickfix-attack-uses-fake-windows-bsod-screens-to-push-malware/
// Unusual use of msbuild.exe to execute code inside .proj file to bypass AV detection
DeviceProcessEvents
| where ( FileName =~ "msbuild.exe" and ProcessCommandLine matches regex @"\\[^\\]\.proj" ) or ( InitiatingProcessFileName =~ "msbuild.exe" and InitiatingProcessCommandLine matches regex @"\\[^\\]\.proj" )

```

