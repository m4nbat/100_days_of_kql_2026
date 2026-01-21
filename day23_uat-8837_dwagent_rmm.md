# Name
UAT-8837 DWAgent RAT

# Description

UAT-8837 deploys DWAgent, a remote administration tool, to make it easier to access the compromised endpoint and drop additional malware to the system:

```
C:\Users\\Downloads\dwagent.exe
C:\Users\\AppData\Local\Temp\dwagent20250909101732\runtime\dwagent.exe -S -m installer
```

# References
- https://blog.talosintelligence.com/uat-8837/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- UAT-8837

# MITRE ATT&CK
-  T1219.002 Remote Access Tools: Remote Desktop Software 

# Data Sources
- M365 Defender
  - DeviceProcessEvents

# Query

```
DeviceProcessEvents
| where FolderPath =~ @"C:\Users\Downloads\dwagent.exe" or FolderPath has_all (@"C:\Users\AppData\Local\Temp\dwagent",@"\runtime\dwagent.exe")
```
