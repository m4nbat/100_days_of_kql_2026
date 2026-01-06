# Name
Filename pattern for RAT dropped in BSOD Clickfix Campaign

# Description
Filename url file dropped in BSOD Clickfix Campaign

Context: 
The “Shortcut” method write a standard INI-style format used by Windows for internet shortcuts:

[InternetShortcut]

URL=file:///C:/windows/Temp/tybd7.exe

This file points to a copy of the RAT malware placed in “C:\Windows\Temp”. The trick is, while “.url” files usually point to websites (http://), Windows allows them to point to local files using the file:// protocol. When Windows starts, it processes the Startup folder, reads this .url file, sees the path, and executes the target executable.

<img width="712" height="219" alt="image" src="https://github.com/user-attachments/assets/ae55f439-5a73-4fed-a007-e132a5d9a217" />

# References
- https://www.securonix.com/blog/analyzing-phaltblyx-how-fake-bsods-and-trusted-build-tools-are-used-to-construct-a-malware-infection/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- PHALT#BLYX
- ASync RAT

# MITRE Techniques
- T1037.005 Boot or Logon Initialization Scripts: Startup Items

# Data Sources
- MDE
  - DeviceFileEvents

# Query

```
// source: https://www.bleepingcomputer.com/news/security/clickfix-attack-uses-fake-windows-bsod-screens-to-push-malware/
// Filename pattern for RAT dropped in clickfix campaign
DeviceFileEvents
| where ActionType =~ "FileCreated" and FolderPath has @"\Windows\Start Menu\Programs\Startup" and FileName =~ "DeleteApp.url"
```


