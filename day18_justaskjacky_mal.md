# Name
Creation of a scheduled task using schtasks.exe in the AppData directory

# Description
**Detection opportunity: Creation of a scheduled task using schtasks.exe in the AppData directory:**
The following pseudo-detection analytic identifies creation of a scheduled task using schtasks.exe in the AppData directory. Threats like JustAskJacky use scheduled tasks to create and maintain persistence on victim systems. Some legitimate installers or administrative activity might also do this, so you may have to add exclusions for legitimate task creation strings in your environment.

# References
- https://redcanary.com/blog/threat-intelligence/intelligence-insights-november-2025/

# Author
- M4nbat

# Socials
- https://www.linkedin.com/in/grjk83/
- @knappresearchlb

# Threats
-  JustAskJacky

# MITRE ATT&CK
- T1053.005 Scheduled Task/Job: Scheduled Task
- T1053 Scheduled Task/Job

# Data Sources
- M365 Defender
  - DeviceProcessEvents

# Query

```
DeviceProcessEvents
|  where InitiatingProcessFileName =~ "cmd.exe" and InitiatingProcessCommandLine has @"appdata\local" and ProcessCommandLine has_all ("schtasks",@"/create",@"appdata\local",@"/xml")

```
