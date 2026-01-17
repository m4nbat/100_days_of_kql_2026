# Name
The ScreenConnect.ClientService binary connecting to a suspicious external domain

# Description
The following pseudo-detection analytic identifies execution of the ScreenConnect.ClientService binary connecting to a suspicious external domain. It is highly unusual for ScreenConnect to initiate network connections to atypical TLDs. Some environments may use custom and/or specific ScreenConnect relays, so additional investigation of the domain’s reputation may be needed.

# References
- https://redcanary.com/blog/threat-intelligence/intelligence-insights-december-2025/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
- ScreenConnect
- Black Basta
- Bl00dy Ransomware Group

# MITRE ATT&CK
- T1219 : Remote Access Tools
- T1219.002 Remote Access Tools: Remote Desktop Software

# Data Sources
- M365 Defender
  - DeviceProcessEvents
  - DeviceNetworkEvents

# Query

## 1

```
DeviceProcessEvents
| where InitiatingProcessFileName in ("ScreenConnect.ClientService.exe") and InitiatingProcessCommandLine  has_any (".top",".info",".site",".tk",".xyz",".pw",".ml",".club",".cf","ws")

```

## 2

```
DeviceProcessEvents
| where InitiatingProcessFileName  in~ ("dfsvc.exe","services.exe") and FileName =~ "ScreenConnect.ClientService.exe" and ProcessCommandline has_any (".top",".info",".site",".tk",".xyz",".pw",".ml",".club",".cf","ws")

```

## 3

```
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "ScreenConnect.ClientService.exe" and RemoteUrl has_any (".top",".info",".site",".tk",".xyz",".pw",".ml",".club",".cf",".ws")

```


